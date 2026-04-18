"""
Automatic seed generation based on output of static dalvik app analysis
v0.1: function signature
v0.2: function signature + constraints on arguments
v0.3: function with a callsequence
"""

import os
import random
import string
from lib.define import *
from lib.utils import get_fuzz_needed_type


random.seed(1234)


INT_RANGES = {
    "jbyte": (-128, 127),
    "jchar": (0, 65535),
    "jshort": (-32768, 32767),
    "jboolean": (0, 1),
    "jint": (-2147483648, 2147483647),
    "jlong": (-9223372036854775808, 9223372036854775807),
}


def random_bytes_length(length):
    """
    generate random bytes of a certain length
    """

    return random.randbytes(length)


def random_bytes_length_LV():
    """
    generate random bytes with LV encoding
    """
    #len_bytes = random.randbytes(GENERIC_SIZE_BYTES)
    #length = int.from_bytes(len_bytes, 'little')
    length = random.randrange(0, 2**(8*GENERIC_SIZE_BYTES))
    len_bytes = length.to_bytes(NR_LV_SIZE_BYTES, 'little')
    data_bytes = random.randbytes(length)
    return len_bytes + data_bytes


def random_bytes_printable_LV():
    """
    generate random printable bytes with LV encoding
    """
    #len_bytes = random.randbytes(GENERIC_SIZE_BYTES)
    #length = int.from_bytes(len_bytes, 'little')
    length = random.randrange(0, 2**(8*GENERIC_SIZE_BYTES))
    len_bytes = length.to_bytes(NR_LV_SIZE_BYTES, 'little')
    data_bytes = b""
    for i in range(0, length):
        data_bytes += bytes([random.randrange(32, 127)])
    return len_bytes + data_bytes


def random_printable_bytes(length):
    data_bytes = b""
    for _ in range(0, length):
        data_bytes += bytes([random.randrange(32, 127)])
    return data_bytes


def to_little_endian_bytes(value, nr_bytes, signed=True):
    return int(value).to_bytes(nr_bytes, "little", signed=signed)


def random_numeric_bytes(jni_type, constraint_kind=None):
    nr_bytes = TYPE2SIZE[jni_type]
    if jni_type == "jfloat":
        return random_bytes_length(4)
    if jni_type == "jdouble":
        return random_bytes_length(8)

    low, high = INT_RANGES[jni_type]
    if constraint_kind == "empty_array_length":
        # Bias to practical array sizes.
        low = 0
        high = 1024
    value = random.randint(low, high)
    signed = jni_type != "jchar" and jni_type != "jboolean"
    return to_little_endian_bytes(value, nr_bytes, signed=signed)


def random_pathish_bytes(length):
    if length <= 0:
        return b""
    templates = [
        "/tmp/input.bin",
        "/var/tmp/a.dat",
        "./data/payload.txt",
        "/sdcard/Download/test.bin",
    ]
    base = random.choice(templates).encode("utf-8")
    if len(base) >= length:
        return base[:length]
    suffix = random_printable_bytes(length - len(base))
    return base + suffix


def get_constraint_kind(arg):
    constraints = arg.get("constraints", {})
    if "filepath" in constraints:
        return "filepath"
    if "filedescriptor" in constraints:
        return "filedescriptor"
    if "empty_array" in constraints:
        return "empty_array"
    return None


def build_seed_plan(arguments):
    """
    Build a normalized plan for seed generation.
    Each entry is a fuzz-consumed input argument.
    """
    plan = []
    for i, arg in enumerate(arguments):
        tofuzz, fuzz_type = get_fuzz_needed_type(arg)
        if not tofuzz:
            continue
        if fuzz_type == "jobject":
            continue
        plan.append(
            {
                "source_index": i,
                "source_arg": arg,
                "type": fuzz_type,
                "LV": False,
                "constraint_kind": get_constraint_kind(arg),
            }
        )
    # Variable-length arguments use LV format unless they are the final fuzz-consumed input.
    for i, entry in enumerate(plan):
        if entry["type"] in TYPE2SIZE:
            continue
        entry["LV"] = i != (len(plan) - 1)
    return plan


def get_seed_constraints(arguments):
    """
    Return a JSON-serializable normalized representation of
    argument-level seed constraints used by the seed planner.
    """
    plan = build_seed_plan(arguments)
    constraints = {
        "nr_seeds": NR_SEEDS,
        "lv_size_bytes": NR_LV_SIZE_BYTES,
        "generic_size_bytes": GENERIC_SIZE_BYTES,
        "entries": [],
    }
    for plan_index, entry in enumerate(plan):
        source_arg = entry["source_arg"]
        constraints["entries"].append(
            {
                "plan_index": plan_index,
                "source_index": entry["source_index"],
                "jni_type": entry["type"],
                "uses_lv_encoding": entry["LV"],
                "constraint_kind": entry["constraint_kind"],
                "raw_constraints": source_arg.get("constraints", {}),
            }
        )
    return constraints


def generate_one_seed_from_plan(plan):
    seed = b""
    for entry in plan:
        arg_type = entry["type"]
        lv_needed = entry["LV"]
        constraint_kind = entry["constraint_kind"]
        if arg_type in TYPE2SIZE:
            seed += random_numeric_bytes(arg_type, constraint_kind=constraint_kind)
            continue

        # Variable-length argument generation.
        if constraint_kind == "filepath":
            length = random.randrange(0, 2 ** (8 * GENERIC_SIZE_BYTES))
            payload = random_pathish_bytes(length)
            if lv_needed:
                seed += length.to_bytes(NR_LV_SIZE_BYTES, "little") + payload
            else:
                seed += payload
        elif constraint_kind == "filedescriptor":
            # File-descriptor constrained args are backed by input bytes in harness code.
            length = random.randrange(0, 2 ** (8 * GENERIC_SIZE_BYTES))
            payload = random_bytes_length(length)
            if lv_needed:
                seed += length.to_bytes(NR_LV_SIZE_BYTES, "little") + payload
            else:
                seed += payload
        else:
            if lv_needed:
                seed += random_bytes_length_LV()
            else:
                seed += random_bytes_length(random.randrange(0, 2 ** (8 * GENERIC_SIZE_BYTES)))
    return seed


def gen_seed_generic(seed_gen_list, LV=True):
    """
    given a list of arguments {"type:": "..", [constraints]}
    generates some seeds that adhere to the input structure
    """
    seed = b""
    for i, arg in enumerate(seed_gen_list):
        arg_type = arg["type"]
        LV_needed = arg["LV"]
        if arg_type in TYPE2SIZE:
            seed += random_bytes_length(TYPE2SIZE[arg_type]) 
        else:
            # handle case for variable-length types
            if LV_needed:
                seed += random_bytes_length_LV()  
            else:
                # if we have to generate random bytes don't make them too large
                seed += random_bytes_length(random.randrange(0, 2**(8*GENERIC_SIZE_BYTES)))
    return seed


def gen_seed_file(seed_gen_list, f_bytes):
    """
    given a list of arguments {"type:": "..", [constraints]}
    generates some seeds that adhere to the input structure
    use the f_bytes to fill byte[] or bytebuffer arguments
    TODO: also use file bytes if constraint is filepath or filedescriptor
    """
    seed = b""
    #TODO: Constraints
    bytes_found = False
    for i, arg in enumerate(seed_gen_list):
        arg_type = arg["type"]
        LV_needed = arg["LV"]
        if arg_type == 'jlong':
            # not fuzzing jlong
            seed += 8 * b"\x00"
            continue
        if arg_type in TYPE2SIZE:
            seed += random_bytes_length(TYPE2SIZE[arg_type])
        elif arg_type == 'jbyteArray' or arg_type == 'ByteBuffer':
            bytes_found = True
            #if input some bytes, 
            if LV_needed:
                seed += len(f_bytes).to_bytes(NR_LV_SIZE_BYTES, 'little') 
                seed += f_bytes
            else:
                seed += f_bytes             
        else:
            # handle case for variable-length types
            if LV_needed:
                seed += random_bytes_length_LV() 
            else:
                seed += random_bytes_length(random.randrange(0, 2**(8*GENERIC_SIZE_BYTES)))
    if bytes_found:
        return seed
    else:
        return None


def gen_file_seeds(seed_gen_list):
    """
    given a list of arguments, generates some seeds that adhere to the structure, filling byte types with the data from well-formed file types 
    """
    output = []
    for file_type in os.listdir("./file_seeds"):
        for f in os.listdir(f"./file_seeds/{file_type}"):
            f_bytes = open(f"./file_seeds/{file_type}/{f}", "rb").read()
            seed = gen_seed_file(seed_gen_list, f_bytes)
            if seed is not None:
                output.append((file_type, seed))
    return output


def gen_seeds(arguments):
    """
    generates a bunch of seeds
    for bytearrays/bytebuffer types, will use some common file types to seed it
    """
    output_seeds = []
    overall_args, LV_args, seed_gen_list = get_nr_arguments_to_fuzz(arguments)
    seed_plan = build_seed_plan(arguments)
    for _ in range(NR_SEEDS):
        # Constraint-aware generation is now the default strategy.
        output_seeds.append(("constraint", generate_one_seed_from_plan(seed_plan)))
    if FILE_SEEDS:
        file_seeds = gen_file_seeds(seed_gen_list)
        output_seeds += file_seeds
    return output_seeds, {"overall": overall_args, "LV": LV_args}, seed_gen_list
    

def get_nr_arguments_to_fuzz(arguments):
    # count the number of arguments that need to be fuzzed, (overall, LV-args)
    overall_args = 0
    LV_args = 0
    seed_gen_list = []
    for i, arg in enumerate(arguments):
        tofuzz, arg_type = get_fuzz_needed_type(arg)
        if not tofuzz:
            continue
        if arg_type == "jobject":
            continue
        if arg_type in TYPE2SIZE:
            overall_args += 1
            seed_gen_list.append({"type": arg_type, "LV": False})
        else:
            # handle case for variable-length types
            if i == len(arguments)-1:
                # if we have to generate random bytes don't make them too large
                overall_args += 1
                seed_gen_list.append({"type": arg_type, "LV": False})
            else:
                LV_args += 1
                overall_args += 1
                seed_gen_list.append({"type": arg_type, "LV": True})
    return overall_args, LV_args, seed_gen_list
