#include "decoder.hpp"

/*
int main(int args, const char** argv) {

    bool use_hard_coded_path = true;
    if (use_hard_coded_path) {
        std::string filename = "C:\\Users\\kala\\code\\computer_enhance_solutions\\solutions\\8086_disasm\\tests\\listing_0052";
        std::string file_contents = read_entire_file(filename);
        std::string result = parse(file_contents);

        std::cout << result << std::endl;
    } else if(args != 2 || argv == nullptr) {
        std::cout << "Usage: decoder.exe <filename>" << std::endl;
    } else {
        std::string filename(argv[1]);
        std::string file_contents = read_entire_file(filename);
        std::string result = parse(file_contents);

        std::cout << result << std::endl;
    }
    return 0;
}
*/

DecodingResult::DecodingResult() :
    decoding_was_successful(false),
    disassembled_instructions_vector({})
{

}

std::string DecodingResult::to_string()
{
    std::string result = "";
    if(!decoding_was_successful) {
        result += "################################################################################\n";
        result += "THERE WAS AN ERROR DURING THE DECODING. OUTPUTTING PARTIAL DECODING RESULT UNTIL ERROR.\n";
        result += "################################################################################\n";
    }
    result += "bits 16\n";

    for(DisassembledInstruction disassembled_instruction: disassembled_instructions_vector) {
        assert(disassembled_instruction.is_valid_disassembly);
        result += disassembled_instruction.disassembly + "\n";
    }

    return result;
}

Decoder::Decoder()
{

}

std::string read_entire_file(const std::string& filename) {
    std::ifstream t(filename);
    std::stringstream file_contents_stream;
    file_contents_stream << t.rdbuf();

    return file_contents_stream.str();
}

DisassembledInstruction Decoder::try_to_parse_instruction_from_input_stream_at_position(const std::string& input_stream, unsigned int current_byte_position)
{
    DisassembledInstruction result;
    result.is_valid_disassembly = false;

    if(current_byte_position < input_stream.size()){
        char current_byte = input_stream[current_byte_position];

        InstructionInfo current_info = parse_instruction_type(current_byte);

        if(current_info.type == InstructionType::UNIDENTIFIED) {
            result.is_valid_disassembly = false;
            return result;
        }

        bool is_next_byte_needed_for_length = is_next_byte_needed_to_determine_length(current_info);
        char next_byte = 0; // set it to zero
        if(is_next_byte_needed_for_length) {
            // check that we actually can read the next byte!
            if (current_byte_position + 1 >= input_stream.size()) {
                result.is_valid_disassembly = false;
                return result;
            }
            next_byte = input_stream[current_byte_position + 1];
        }
        // pass in current_byte and next_byte, which is 0 if its not needed to determine the length.
        determine_instruction_length(current_info, current_byte, next_byte);

        // we have determined the length of the instruction at this point and its type.
        assert(current_info.instruction_length > 0);

        // now read that many bytes and fill out the instruction info.
        // first check if we can actually read that many bytes
        if (current_byte_position + current_info.instruction_length - 1 >= input_stream.size()) {
            result.is_valid_disassembly = false;
            return result;
        }

        // collect all the bytes for the current instruction
        std::array < char, MAX_INSTRUCTION_LENGTH > instruction_data;
        assert(current_info.instruction_length <= instruction_data.size());
        for (int i = 0; i < current_info.instruction_length; i++) {
            instruction_data[i] = input_stream[current_byte_position + i];
        }

        // fill out instruction info
        fill_out_instruction_info(current_info, instruction_data);
        result.disassembly = disassemble_instruction_from_info(current_info);

        result.starting_byte_position = current_byte_position;
        result.instruction_length_in_bytes = current_info.instruction_length;
        result.instruction_data = instruction_data;

        result.is_valid_disassembly = true;
    }
    return result;
}

DecodingResult Decoder::try_to_parse_input_stream(const std::string& input_stream) {
    DecodingResult decoding_result;
    decoding_result.decoding_was_successful = true;

    std::size_t current_byte_position = 0;
    while(current_byte_position < input_stream.size()) {
        if(current_byte_position == 227) {
            std::cout << "xd" << std::endl;
        }
        DisassembledInstruction current_instruction_result = try_to_parse_instruction_from_input_stream_at_position(input_stream, current_byte_position);

        if(current_instruction_result.is_valid_disassembly) {
            decoding_result.disassembled_instructions_vector.push_back(current_instruction_result);
            current_byte_position += current_instruction_result.instruction_length_in_bytes; // advance the position by the length of the instruction
        } else {
            decoding_result.decoding_was_successful = false;
            break;
        }
    }

    return decoding_result;
}


InstructionInfo Decoder::parse_instruction_type(char data) {
    InstructionInfo info;
    info.type = InstructionType::UNIDENTIFIED;

    int value = data;
    value = value & 0xff;

    // we first see if its some stupid push/pop instruction, which are special cases.
    int hi_3_bits = value & 0b11100000;
    int lo_3_bits = value & 0b00000111;

    if (hi_3_bits == 0b00000000) {
        switch (lo_3_bits) {
        case 0b00000110:
            info.type = InstructionType::PUSH_SEGMENT_REGISTER;
            break;
        case 0b00000111:
            info.type = InstructionType::POP_SEGMENT_REGISTER;
            break;
        default:
            break;
        }
    }

    if (info.type == InstructionType::UNIDENTIFIED) {
        value = data; // put data into an int, so we can use a switch statement here (binary literals are of type int!)
        // but we dont want to sign extend here, so we additionally have to mask here
        value = value & 0xff;

        // check full 8-bits
        switch (value) {
        case 0b10001110:
            info.type = InstructionType::MOV_REGISTER_OR_MEMORY_TO_SEGMENT_REGISTER;
            break;
        case 0b10001100:
            info.type = InstructionType::MOV_SEGMENT_REGISTER_TO_REGISTER_OR_MEMORY;
            break;
        case 0b01110100:
            info.type = InstructionType::RET_JE_OR_JZE;
            break;
        case 0b01111100:
            info.type = InstructionType::RET_JL_OR_JNGE;
            break;
        case 0b01111110:
            info.type = InstructionType::RET_JLE_OR_JNG;
            break;
        case 0b01110010:
            info.type = InstructionType::RET_JB_OR_JNA;
            break;
        case 0b01110110:
            info.type = InstructionType::RET_JBE_OR_JNA;
            break;
        case 0b01111010:
            info.type = InstructionType::RET_JP_OR_JPE;
            break;
        case 0b01110000:
            info.type = InstructionType::RET_JO;
            break;
        case 0b01111000:
            info.type = InstructionType::RET_JS;
            break;
        case 0b01110101:
            info.type = InstructionType::RET_JNE_OR_JNZ;
            break;
        case 0b01111101:
            info.type = InstructionType::RET_JNL_OR_JGE;
            break;
        case 0b01111111:
            info.type = InstructionType::RET_JNLE_OR_JG;
            break;
        case 0b01110011:
            info.type = InstructionType::RET_JNB_OR_JAE;
            break;
        case 0b01110111:
            info.type = InstructionType::RET_JNBE_OR_JA;
            break;
        case 0b01111011:
            info.type = InstructionType::RET_JNP_OR_JPO;
            break;
        case 0b01110001:
            info.type = InstructionType::RET_JNO;
            break;
        case 0b01111001:
            info.type = InstructionType::RET_JNS;
            break;
        case 0b11100010:
            info.type = InstructionType::RET_LOOP;
            break;
        case 0b11100001:
            info.type = InstructionType::RET_LOOPZ_OR_LOOPE;
            break;
        case 0b11100000:
            info.type = InstructionType::RET_LOOPNZ_OR_LOOPNE;
            break;
        case 0b11100011:
            info.type = InstructionType::RET_JCXZ;
            break;
        case 0b11111111:
            info.type = InstructionType::PUSH_REGISTER_OR_MEMORY;
            break;
        case 0b10001111:
            info.type = InstructionType::POP_REGISTER_OR_MEMORY;
            break;
        case 0b11010111:
            info.type = InstructionType::XLAT;
            break;
        case 0b10001101:
            info.type = InstructionType::LEA;
            break;
        case 0b11000101:
            info.type = InstructionType::LDS;
            break;
        case 0b11000100:
            info.type = InstructionType::LES;
            break;
        case 0b10011111:
            info.type = InstructionType::LAHF;
            break;
        case 0b10011110:
            info.type = InstructionType::SAHF;
            break;
        case 0b10011100:
            info.type = InstructionType::PUSHF;
            break;
        case 0b10011101:
            info.type = InstructionType::POPF;
            break;
        default:
            break;
        }
    }
    if (info.type == InstructionType::UNIDENTIFIED) {
        // check 7-bits
        int value_7_bits_masked = value & 0b11111110;
        switch (value_7_bits_masked) {
        case 0b11000110:
            info.type = InstructionType::MOV_IMMEDIATE_TO_REGISTER_OR_MEMORY;
            break;
        case 0b10100000:
            info.type = InstructionType::MOV_MEMORY_TO_ACCUMULATOR;
            break;
        case 0b10100010:
            info.type = InstructionType::MOV_ACCUMULATOR_TO_MEMORY;
            break;
        case 0b00000100:
            info.type = InstructionType::ADD_IMMEDIATE_TO_ACCUMULATOR;
            break;
        case 0b00010100:
            info.type = InstructionType::ADC_IMMEDIATE_TO_ACCUMULATOR;
            break;
        case 0b00101100:
            info.type = InstructionType::SUB_IMMEDIATE_FROM_ACCUMULATOR;
            break;
        case 0b00011100:
            info.type = InstructionType::SBB_IMMEDIATE_FROM_ACCUMULATOR;
            break;
        case 0b00111100:
            info.type = InstructionType::CMP_IMMEDIATE_WITH_ACCUMULATOR;
            break;
        case 0b10000110:
            info.type = InstructionType::XCHG_REGISTER_OR_MEMORY_WITH_REGISTER;
            break;
        case 0b11100100:
            info.type = InstructionType::IN_FIXED_PORT;
            break;
        case 0b11101100:
            info.type = InstructionType::IN_VARIABLE_PORT;
            break;
        case 0b11100110:
            info.type = InstructionType::OUT_FIXED_PORT;
            break;
        case 0b11101110:
            info.type = InstructionType::OUT_VARIABLE_PORT;
            break;
        default:
            break;
        }
    }

    if (info.type == InstructionType::UNIDENTIFIED) {
        // parse instructions, uniquely identified by first six bits, last two bits arbitrary

        // CAREFUL: zero extend the char and consider it as an int, otherwise we cant use binary literals in the switch statement below,
        // binary literals are of type int.

        // check 6-bits
        int value_6_bits_masked = data & 0b11111100;
        switch (value_6_bits_masked) {
        case 0b10001000:
            info.type = InstructionType::MOV_REGISTER_OR_MEMORY_TO_OR_FROM_REGISTER;
            break;
        case 0b10000000:
            info.type = InstructionType::ARITHMETIC_IMMEDIATE_TO_OR_WITH_REGISTER_OR_MEMORY;
            break;
        case 0b00000000:
            info.type = InstructionType::ADD_REGISTER_OR_MEMORY_WITH_REGISTER_TO_EITHER;
            break;
        case 0b00010000:
            info.type = InstructionType::ADC_REGISTER_OR_MEMORY_WITH_REGISTER_TO_EITHER;
            break;
        case 0b00101000:
            info.type = InstructionType::SUB_REGISTER_OR_MEMORY_WITH_REGISTER_TO_EITHER;
            break;
        case 0b00011000:
            info.type = InstructionType::SBB_REGISTER_OR_MEMORY_WITH_REGISTER_TO_EITHER;
            break;
        case 0b00111000:
            info.type = InstructionType::CMP_REGISTER_OR_MEMORY_WITH_REGISTER_TO_EITHER;
            break;
        default:
            break;
        }
    }

    if (info.type == InstructionType::UNIDENTIFIED) {
        // check 5-bits
        int value_5_bits_masked = value & 0b11111000;
        switch (value_5_bits_masked) {
        case 0b01010000:
            info.type = InstructionType::PUSH_REGISTER;
            break;
        case 0b01011000:
            info.type = InstructionType::POP_REGISTER;
            break;
        case 0b10010000:
            info.type = InstructionType::XCHG_REGISTER_WITH_ACCUMULATOR;
            break;
        default:
            break;
        }
    }

    if (info.type == InstructionType::UNIDENTIFIED) {
        // check 4-bits
        int value_4_bits_masked = value & 0b11110000;
        switch (value_4_bits_masked) {
        case 0b10110000:
            info.type = InstructionType::MOV_IMMEDIATE_TO_REGISTER;
            break;
        default:
            break;
        }
    }


    if (info.type == InstructionType::UNIDENTIFIED) {
        std::cout << "Error. Could not identify instruction.\n";
    }
    return info;
}

bool Decoder::is_next_byte_needed_to_determine_length(InstructionInfo& info) {
    bool is_needed = false;
    switch (info.type) {
    case MOV_REGISTER_OR_MEMORY_TO_OR_FROM_REGISTER:  // fallthrough
    case MOV_IMMEDIATE_TO_REGISTER_OR_MEMORY: // fallthrough
    case MOV_IMMEDIATE_TO_REGISTER: // fallthrough
    case MOV_REGISTER_OR_MEMORY_TO_SEGMENT_REGISTER: // fallthrough
    case MOV_SEGMENT_REGISTER_TO_REGISTER_OR_MEMORY: // fallthrough
    case ARITHMETIC_IMMEDIATE_TO_OR_WITH_REGISTER_OR_MEMORY: // fallthrough
    case ADD_REGISTER_OR_MEMORY_WITH_REGISTER_TO_EITHER: // fallthrough
    case ADC_REGISTER_OR_MEMORY_WITH_REGISTER_TO_EITHER: // fallthrough
    case SUB_REGISTER_OR_MEMORY_WITH_REGISTER_TO_EITHER: // fallthrough
    case SBB_REGISTER_OR_MEMORY_WITH_REGISTER_TO_EITHER: // fallthrough
    case CMP_REGISTER_OR_MEMORY_WITH_REGISTER_TO_EITHER: // fallthrough
    case PUSH_REGISTER_OR_MEMORY: // fallthrough
    case POP_REGISTER_OR_MEMORY: // fallthrough
    case XCHG_REGISTER_OR_MEMORY_WITH_REGISTER: // fallthrough
    case LEA: // fallthrough
    case LDS: // fallthrough
    case LES:
        is_needed = true;
        break;
    case InstructionTypeEnumLength: // fallthrough to default
    case MOV_MEMORY_TO_ACCUMULATOR: // fallthrough to default
    case MOV_ACCUMULATOR_TO_MEMORY: // fallthrough to default
    case ADD_IMMEDIATE_TO_ACCUMULATOR: // fallthrough to default
    case ADC_IMMEDIATE_TO_ACCUMULATOR: // fallthrough to default
    case SUB_IMMEDIATE_FROM_ACCUMULATOR: // fallthrough to default
    case SBB_IMMEDIATE_FROM_ACCUMULATOR: // fallthrough to default
    case CMP_IMMEDIATE_WITH_ACCUMULATOR: // fallthrough to default
    case RET_JE_OR_JZE: // fallthrough to default
    case RET_JL_OR_JNGE: // fallthrough to default
    case RET_JLE_OR_JNG: // fallthrough to default
    case RET_JB_OR_JNA: // fallthrough to default
    case RET_JBE_OR_JNA: // fallthrough to default
    case RET_JP_OR_JPE: // fallthrough to default
    case RET_JO: // fallthrough to default
    case RET_JS: // fallthrough to default
    case RET_JNE_OR_JNZ: // fallthrough to default
    case RET_JNL_OR_JGE: // fallthrough to default
    case RET_JNLE_OR_JG: // fallthrough to default
    case RET_JNB_OR_JAE: // fallthrough to default
    case RET_JNBE_OR_JA: // fallthrough to default
    case RET_JNP_OR_JPO: // fallthrough to default
    case RET_JNO: // fallthrough to default
    case RET_JNS: // fallthrough to default
    case RET_LOOP: // fallthrough to default
    case RET_LOOPZ_OR_LOOPE: // fallthrough to default
    case RET_LOOPNZ_OR_LOOPNE: // fallthrough to default
    case RET_JCXZ: // fallthrough to default
    case PUSH_REGISTER: // fallthrough to default
    case PUSH_SEGMENT_REGISTER: // fallthrough to default
    case POP_REGISTER: // fallthrough to default
    case POP_SEGMENT_REGISTER: // fallthrough to default
    case XCHG_REGISTER_WITH_ACCUMULATOR: // fallthrough to default
    case IN_FIXED_PORT: // fallthrough to default
    case IN_VARIABLE_PORT: // fallthrough to default
    case OUT_FIXED_PORT: // fallthrough to default
    case OUT_VARIABLE_PORT: // fallthrough to default
    case XLAT: // fallthrough to default
    case LAHF: // fallthrough to default
    case SAHF: // fallthrough to default
    case PUSHF: // fallthrough to default
    case POPF: // fallthrough to default
    case UNIDENTIFIED: // fallthrough to default
    default:
        is_needed = false;
        break;
    }
    return is_needed;
}

unsigned int Decoder::determine_displacement_length_from_second_byte(char data) {
    // mod_data and rm_data are always at the same position for the entire instruction set.
    int mod_data = (data & 0b11000000) >> 6;
    int rm_data = data & 0b00000111;

    unsigned int displacement_length = 0;
    switch (mod_data) {
    case 0b00:
        if (rm_data == 0b110) {
            displacement_length = 2;
        } else {
            displacement_length = 0;
        }
        break;
    case 0b01:
        displacement_length = 1;
        break;
    case 0b10:
        displacement_length = 2;
        break;
    case 0b11:
        displacement_length = 0;
        break;
    default:
        break;
    }
    return displacement_length;
}


void Decoder::determine_instruction_length(InstructionInfo& info, char first_byte, char second_byte) {
    int w_field_value = 0;
    int s_field_value = 0;
    switch (info.type) {
    case MOV_IMMEDIATE_TO_REGISTER_OR_MEMORY:
        info.base_length = 2;
        info.displacement_length = determine_displacement_length_from_second_byte(second_byte);

        info.data_length = 1;
        w_field_value = first_byte & 0b00000001;
        if (w_field_value) {
            info.data_length = 2;
        }
        break;
    case MOV_IMMEDIATE_TO_REGISTER:
        info.base_length = 1;

        info.data_length = 1;
        w_field_value = first_byte & 0b00001000;
        if (w_field_value) {
            info.data_length = 2;
        }
        break;
    case MOV_MEMORY_TO_ACCUMULATOR: // fallthrough
    case MOV_ACCUMULATOR_TO_MEMORY:
        info.base_length = 1;
        info.address_length = 2;
        break;

    case ARITHMETIC_IMMEDIATE_TO_OR_WITH_REGISTER_OR_MEMORY:
        info.base_length = 2;
        info.displacement_length = determine_displacement_length_from_second_byte(second_byte);

        w_field_value = first_byte & 0b00000001;
        s_field_value = first_byte & 0b00000010;

        if (s_field_value == 0 && w_field_value == 1) {
            info.data_length = 2;
        } else {
            info.data_length = 1;
        }
        break;
    case ADD_IMMEDIATE_TO_ACCUMULATOR: // fallthrough
    case ADC_IMMEDIATE_TO_ACCUMULATOR: // fallthrough
    case SUB_IMMEDIATE_FROM_ACCUMULATOR: // fallthrough
    case SBB_IMMEDIATE_FROM_ACCUMULATOR: // fallthrough
    case CMP_IMMEDIATE_WITH_ACCUMULATOR:
        info.base_length = 1;
        info.data_length = 1;
        w_field_value = first_byte & 0b00000001;
        if (w_field_value) {
            info.data_length = 2;
        }
        break;
    case MOV_REGISTER_OR_MEMORY_TO_OR_FROM_REGISTER: // fallthrough
    case MOV_REGISTER_OR_MEMORY_TO_SEGMENT_REGISTER: // fallthrough
    case MOV_SEGMENT_REGISTER_TO_REGISTER_OR_MEMORY: // fallthrough
    case ADD_REGISTER_OR_MEMORY_WITH_REGISTER_TO_EITHER: // fallthrough
    case ADC_REGISTER_OR_MEMORY_WITH_REGISTER_TO_EITHER: // fallthrough
    case SUB_REGISTER_OR_MEMORY_WITH_REGISTER_TO_EITHER: // fallthrough
    case SBB_REGISTER_OR_MEMORY_WITH_REGISTER_TO_EITHER: // fallthrough
    case CMP_REGISTER_OR_MEMORY_WITH_REGISTER_TO_EITHER: // fallthrough
    case PUSH_REGISTER_OR_MEMORY: // fallthrough
    case POP_REGISTER_OR_MEMORY: // fallthrough
    case XCHG_REGISTER_OR_MEMORY_WITH_REGISTER: // fallthrough
    case LEA: // fallthrough
    case LDS: // fallthrough
    case LES:
        info.base_length = 2;
        info.displacement_length = determine_displacement_length_from_second_byte(second_byte);
        break;
    case RET_JE_OR_JZE: // fallthrough
    case RET_JL_OR_JNGE: // fallthrough
    case RET_JLE_OR_JNG: // fallthrough
    case RET_JB_OR_JNA: // fallthrough
    case RET_JBE_OR_JNA: // fallthrough
    case RET_JP_OR_JPE: // fallthrough
    case RET_JO: // fallthrough
    case RET_JS: // fallthrough
    case RET_JNE_OR_JNZ: // fallthrough
    case RET_JNL_OR_JGE: // fallthrough
    case RET_JNLE_OR_JG: // fallthrough
    case RET_JNB_OR_JAE: // fallthrough
    case RET_JNBE_OR_JA: // fallthrough
    case RET_JNP_OR_JPO: // fallthrough
    case RET_JNO: // fallthrough
    case RET_JNS: // fallthrough
    case RET_LOOP: // fallthrough
    case RET_LOOPZ_OR_LOOPE: // fallthrough
    case RET_LOOPNZ_OR_LOOPNE: // fallthrough
    case RET_JCXZ:
        info.base_length = 1;
        info.ip_inc8_length = 1;
        break;
    case PUSH_REGISTER: // fallthrough
    case PUSH_SEGMENT_REGISTER: // fallthrough
    case POP_REGISTER: // fallthrough
    case POP_SEGMENT_REGISTER: // fallthrough
    case XCHG_REGISTER_WITH_ACCUMULATOR: // fallthrough
    case IN_VARIABLE_PORT: // fallthrough
    case OUT_VARIABLE_PORT: // fallthrough
    case XLAT: // fallthrough
    case LAHF: // fallthrough
    case SAHF: // fallthrough
    case PUSHF: // fallthrough
    case POPF:
        info.base_length = 1;
        break;
    case IN_FIXED_PORT: // fallthrough
    case OUT_FIXED_PORT:
        info.base_length = 1;
        info.data8_length = 1;
        break;
    case InstructionTypeEnumLength: // fallthrough to default
    case UNIDENTIFIED: // fallthrough to default
    default:
        break;
    }
    info.instruction_length = info.base_length + info.displacement_length + info.data_length + info.address_length + info.ip_inc8_length + info.data8_length;
}

void Decoder::fill_out_instruction_info(InstructionInfo& info, std::array < char, MAX_INSTRUCTION_LENGTH > & instruction_data) {
    assert(info.instruction_length == info.base_length + info.displacement_length + info.data_length + info.address_length + info.ip_inc8_length + info.data8_length);
    switch (info.type) {
    case InstructionType::MOV_REGISTER_OR_MEMORY_TO_OR_FROM_REGISTER:
        assert(info.base_length == 2);
        assert(info.displacement_length == 0 || info.displacement_length == 1 || info.displacement_length == 2);
        assert(info.data_length == 0 && info.address_length == 0);

        info.instruction_d = (instruction_data[0] & 0b00000010) > 1;
        info.instruction_w = instruction_data[0] & 0b00000001;
        info.instruction_mod = (instruction_data[1] & 0b11000000) >> 6;
        info.instruction_reg = (instruction_data[1] & 0b00111000) >> 3;
        info.instruction_rm = instruction_data[1] & 0b00000111;
        if (info.displacement_length > 0) {
            if (info.displacement_length == 1) {
                info.instruction_disp_lo = instruction_data[2];
            } else if (info.displacement_length == 2) {
                info.instruction_disp_lo = instruction_data[2];
                info.instruction_disp_hi = instruction_data[3];
            }
        }
        break;
    case MOV_IMMEDIATE_TO_REGISTER_OR_MEMORY:
        assert(info.base_length == 2);
        assert(info.displacement_length == 0 || info.displacement_length == 1 || info.displacement_length == 2);
        assert(info.data_length == 1 || info.data_length == 2);
        assert(info.address_length == 0);

        info.instruction_w = instruction_data[0] & 0b00000001;
        info.instruction_mod = (instruction_data[1] & 0b11000000) >> 6;
        info.instruction_rm = instruction_data[1] & 0b00000111;


        if (info.displacement_length > 0) {
            if (info.displacement_length == 1) {
                info.instruction_disp_lo = instruction_data[2];
            } else if (info.displacement_length == 2) {
                info.instruction_disp_lo = instruction_data[2];
                info.instruction_disp_hi = instruction_data[3];
            }
        }

        if (info.data_length == 1) {
            info.instruction_data_field = instruction_data[2 + info.displacement_length];
        } else if (info.data_length == 2) {
            info.instruction_data_field = instruction_data[2 + info.displacement_length];
            info.instruction_data_extended_field = instruction_data[3 + info.displacement_length];
        }

        break;
    case MOV_IMMEDIATE_TO_REGISTER:
        assert(info.base_length == 1);
        assert(info.data_length == 1 || info.data_length == 2);
        assert(info.displacement_length == 0 && info.address_length == 0);

        info.instruction_w = (instruction_data[0] & 0b00001000) >> 3;
        info.instruction_reg = instruction_data[0] & 0b00000111;

        if (info.data_length == 1) {
            info.instruction_data_field = instruction_data[1];
        } else if (info.data_length == 2) {
            info.instruction_data_field = instruction_data[1];
            info.instruction_data_extended_field = instruction_data[2];
        }

        break;
    case MOV_MEMORY_TO_ACCUMULATOR: // fallthrough
    case MOV_ACCUMULATOR_TO_MEMORY:
        assert(info.base_length == 1);
        assert(info.address_length == 2);
        assert(info.displacement_length == 0 && info.data_length == 0);


        info.instruction_w = (instruction_data[0] & 0b00001000) >> 3;
        info.instruction_address_lo = instruction_data[1];
        info.instruction_address_hi = instruction_data[2];
        break;
    case MOV_REGISTER_OR_MEMORY_TO_SEGMENT_REGISTER: // fallthrough
    case MOV_SEGMENT_REGISTER_TO_REGISTER_OR_MEMORY:
        assert(info.base_length == 2);
        assert(info.displacement_length == 0 || info.displacement_length == 1 || info.displacement_length == 2);
        assert(info.address_length == 0 && info.data_length == 0);

        info.instruction_mod = (instruction_data[1] & 0b11000000) >> 6;
        info.instruction_sr = (instruction_data[0] & 0b00011000) >> 3;
        info.instruction_rm = instruction_data[1] & 0b00000111;

        if (info.displacement_length > 0) {
            if (info.displacement_length == 1) {
                info.instruction_disp_lo = instruction_data[2];
            } else if (info.displacement_length == 2) {
                info.instruction_disp_lo = instruction_data[2];
                info.instruction_disp_hi = instruction_data[3];
            }
        }

        break;
    case ARITHMETIC_IMMEDIATE_TO_OR_WITH_REGISTER_OR_MEMORY:
        assert(info.base_length == 2);
        assert(info.displacement_length == 0 || info.displacement_length == 1 || info.displacement_length == 2);
        assert(info.data_length == 1 || info.data_length == 2 && info.address_length == 0);

        info.instruction_s = (instruction_data[0] & 0b00000010) > 1;
        info.instruction_w = instruction_data[0] & 0b00000001;
        info.instruction_mod = (instruction_data[1] & 0b11000000) >> 6;
        info.instruction_reg = (instruction_data[1] & 0b00111000) >> 3;
        info.instruction_rm = instruction_data[1] & 0b00000111;

        if (info.displacement_length > 0) {
            if (info.displacement_length == 1) {
                info.instruction_disp_lo = instruction_data[2];
            } else if (info.displacement_length == 2) {
                info.instruction_disp_lo = instruction_data[2];
                info.instruction_disp_hi = instruction_data[3];
            }
        }

        info.instruction_data_field = instruction_data[info.base_length + info.displacement_length];
        if (info.data_length == 2) {
            info.instruction_data_extended_field = instruction_data[info.base_length + info.displacement_length + 1];
        }
        break;
    case ADD_REGISTER_OR_MEMORY_WITH_REGISTER_TO_EITHER: // fallthrough
    case ADC_REGISTER_OR_MEMORY_WITH_REGISTER_TO_EITHER: // fallthrough
    case SUB_REGISTER_OR_MEMORY_WITH_REGISTER_TO_EITHER: // fallthrough
    case SBB_REGISTER_OR_MEMORY_WITH_REGISTER_TO_EITHER: // fallthrough
    case CMP_REGISTER_OR_MEMORY_WITH_REGISTER_TO_EITHER:
        assert(info.base_length == 2);
        assert(info.displacement_length == 0 || info.displacement_length == 1 || info.displacement_length == 2);
        assert(info.data_length == 0 && info.address_length == 0);

        info.instruction_d = (instruction_data[0] & 0b00000010) > 1;
        info.instruction_w = instruction_data[0] & 0b00000001;
        info.instruction_mod = (instruction_data[1] & 0b11000000) >> 6;
        info.instruction_reg = (instruction_data[1] & 0b00111000) >> 3;
        info.instruction_rm = instruction_data[1] & 0b00000111;
        if (info.displacement_length > 0) {
            if (info.displacement_length == 1) {
                info.instruction_disp_lo = instruction_data[2];
            } else if (info.displacement_length == 2) {
                info.instruction_disp_lo = instruction_data[2];
                info.instruction_disp_hi = instruction_data[3];
            }
        }
        break;
    case ADD_IMMEDIATE_TO_ACCUMULATOR: // fallthrough
    case ADC_IMMEDIATE_TO_ACCUMULATOR: // fallthrough
    case SUB_IMMEDIATE_FROM_ACCUMULATOR: // fallthrough
    case SBB_IMMEDIATE_FROM_ACCUMULATOR: // fallthrough
    case CMP_IMMEDIATE_WITH_ACCUMULATOR:
        assert(info.base_length == 1);
        assert(info.data_length == 1 || info.data_length == 2);
        assert(info.displacement_length == 0 && info.address_length == 0);

        info.instruction_w = instruction_data[0] & 0b00000001;

        if (info.data_length == 1) {
            info.instruction_data_field = instruction_data[1];
        } else if (info.data_length == 2) {
            info.instruction_data_field = instruction_data[1];
            info.instruction_data_extended_field = instruction_data[2];
        }
        break;
    case RET_JE_OR_JZE: // fallthrough
    case RET_JL_OR_JNGE: // fallthrough
    case RET_JLE_OR_JNG: // fallthrough
    case RET_JB_OR_JNA: // fallthrough
    case RET_JBE_OR_JNA: // fallthrough
    case RET_JP_OR_JPE: // fallthrough
    case RET_JO: // fallthrough
    case RET_JS: // fallthrough
    case RET_JNE_OR_JNZ: // fallthrough
    case RET_JNL_OR_JGE: // fallthrough
    case RET_JNLE_OR_JG: // fallthrough
    case RET_JNB_OR_JAE: // fallthrough
    case RET_JNBE_OR_JA: // fallthrough
    case RET_JNP_OR_JPO: // fallthrough
    case RET_JNO: // fallthrough
    case RET_JNS: // fallthrough
    case RET_LOOP: // fallthrough
    case RET_LOOPZ_OR_LOOPE: // fallthrough
    case RET_LOOPNZ_OR_LOOPNE: // fallthrough
    case RET_JCXZ:
        info.instruction_ip_inc8 = instruction_data[1];
        break;
    case PUSH_REGISTER_OR_MEMORY: // fallthrough
    case POP_REGISTER_OR_MEMORY:
        assert(info.base_length == 2);
        assert(info.displacement_length == 0 || info.displacement_length == 1 || info.displacement_length == 2);
        assert(info.address_length == 0 && info.data_length == 0);

        info.instruction_mod = (instruction_data[1] & 0b11000000) >> 6;
        info.instruction_rm = instruction_data[1] & 0b00000111;

        if (info.displacement_length > 0) {
            if (info.displacement_length == 1) {
                info.instruction_disp_lo = instruction_data[2];
            } else if (info.displacement_length == 2) {
                info.instruction_disp_lo = instruction_data[2];
                info.instruction_disp_hi = instruction_data[3];
            }
        }
        break;
    case XCHG_REGISTER_OR_MEMORY_WITH_REGISTER:
        assert(info.base_length == 2);
        assert(info.displacement_length == 0 || info.displacement_length == 1 || info.displacement_length == 2);
        assert(info.address_length == 0 && info.data_length == 0);


        info.instruction_w = instruction_data[0] & 0b00000001;
        info.instruction_mod = (instruction_data[1] & 0b11000000) >> 6;
        info.instruction_reg = (instruction_data[1] & 0b00111000) >> 3;
        info.instruction_rm = instruction_data[1] & 0b00000111;

        if (info.displacement_length > 0) {
            if (info.displacement_length == 1) {
                info.instruction_disp_lo = instruction_data[2];
            } else if (info.displacement_length == 2) {
                info.instruction_disp_lo = instruction_data[2];
                info.instruction_disp_hi = instruction_data[3];
            }
        }
        break;
    case LEA: // fallthrough
    case LDS: // fallthrough
    case LES:
        assert(info.base_length == 2);
        assert(info.displacement_length == 0 || info.displacement_length == 1 || info.displacement_length == 2);
        assert(info.address_length == 0 && info.data_length == 0);

        info.instruction_mod = (instruction_data[1] & 0b11000000) >> 6;
        info.instruction_reg = (instruction_data[1] & 0b00111000) >> 3;
        info.instruction_rm = instruction_data[1] & 0b00000111;

        if (info.displacement_length > 0) {
            if (info.displacement_length == 1) {
                info.instruction_disp_lo = instruction_data[2];
            } else if (info.displacement_length == 2) {
                info.instruction_disp_lo = instruction_data[2];
                info.instruction_disp_hi = instruction_data[3];
            }
        }
        break;
    case PUSH_REGISTER: // fallthrough
    case POP_REGISTER: // fallthrough
    case XCHG_REGISTER_WITH_ACCUMULATOR:
        info.instruction_reg = instruction_data[0] & 0b00000111;
        break;
    case PUSH_SEGMENT_REGISTER: // fallthrough
    case POP_SEGMENT_REGISTER:
        info.instruction_reg = (instruction_data[0] & 0b00011100) >> 2;
        break;
    case IN_FIXED_PORT: // fallthrough
    case OUT_FIXED_PORT:
        info.instruction_w = instruction_data[0] & 0b00000001;
        info.instruction_data8 = instruction_data[1];
        break;
    case IN_VARIABLE_PORT: // fallthrough
    case OUT_VARIABLE_PORT:
        info.instruction_w = instruction_data[0] & 0b00000001;
        break;
    case XLAT: // fallthrough
    case LAHF: // fallthrough
    case SAHF: // fallthrough
    case PUSHF: // fallthrough
    case POPF:
        // dont need to fill out anything, these are 1-byte instructions, uniquely specified by their opcode/info.type.
        break;
    case InstructionTypeEnumLength: // fallthrough to default
    case UNIDENTIFIED: // fallthrough to default
    default:
        break;
    }
}

std::string Decoder::parse_instruction_infos(const std::vector < InstructionInfo > & instruction_infos) {
    std::string result;
    result.append("bits 16\n");

    for (const InstructionInfo& info: instruction_infos) {
        std::string instr_result = disassemble_instruction_from_info(info);
        result += instr_result + "\n";
    }
    return result;
}

std::string Decoder::disassemble_instruction_from_info(const InstructionInfo& info) {
    std::string disassembly = "";

    std::string mnemonic = determine_mnemonic_from_info(info);
    std::string src_operand = "";
    std::string dst_operand = "";
    std::string immediate_size_string = "";
    std::string displacement_size_string = "";

    short immediate_value = 0;
    short address_value = 0;

    switch (info.type) {
    case MOV_REGISTER_OR_MEMORY_TO_OR_FROM_REGISTER:
        dst_operand = instruction_decode_effective_address(info, info.instruction_rm);
        src_operand = decode_register_name(info.instruction_reg, info.instruction_w);

        // if the d field is set swap the order of the dst, src registers.
        if (info.instruction_d) {
            std::swap(src_operand, dst_operand);
        }


        disassembly = mnemonic + " " + dst_operand + ", " + src_operand;
        break;
    case MOV_IMMEDIATE_TO_REGISTER_OR_MEMORY:
        if (info.instruction_w == 0) {
            immediate_size_string = "BYTE";
        } else if (info.instruction_w == 1) {
            immediate_size_string = "WORD";
        }
        immediate_value = stitch_lower_and_higher_bytes_to_2_byte_value(info.instruction_data_field, info.instruction_data_extended_field); // if data_length is 1, then info.instruction_data_extended_field is zero!

        src_operand =  std::to_string(immediate_value);
        dst_operand = instruction_decode_effective_address(info, info.instruction_rm);

        disassembly = mnemonic + " " + dst_operand + ", " + immediate_size_string + " " + src_operand;
        break;
    case MOV_IMMEDIATE_TO_REGISTER:
        if (info.instruction_w == 0) {
            immediate_size_string = "BYTE";
        } else if (info.instruction_w == 1) {
            immediate_size_string = "WORD";
        }
        immediate_value = stitch_lower_and_higher_bytes_to_2_byte_value(info.instruction_data_field, info.instruction_data_extended_field); // if data_length is 1, then info.instruction_data_extended_field is zero!

        src_operand = std::to_string(immediate_value);
        dst_operand = decode_register_name(info.instruction_reg, info.instruction_w);

        disassembly = mnemonic + " " + dst_operand + ", " + immediate_size_string + " " + src_operand;
        break;
    case MOV_MEMORY_TO_ACCUMULATOR:
        assert(info.address_length == 2);

        address_value = stitch_lower_and_higher_bytes_to_2_byte_value(info.instruction_address_lo, info.instruction_address_hi);

        src_operand = "[" + std::to_string(address_value) + "]";
        dst_operand = "AX";

        disassembly = mnemonic + " " + dst_operand + ", " + src_operand;
        break;
    case MOV_ACCUMULATOR_TO_MEMORY:
        assert(info.address_length == 2);

        address_value = stitch_lower_and_higher_bytes_to_2_byte_value(info.instruction_address_lo, info.instruction_address_hi);

        src_operand = "AX";
        dst_operand = "[" + std::to_string(address_value) + "]";

        disassembly = mnemonic + " " + dst_operand + ", " + src_operand;
        break;
    case MOV_REGISTER_OR_MEMORY_TO_SEGMENT_REGISTER:
        // TODO
        break;
    case MOV_SEGMENT_REGISTER_TO_REGISTER_OR_MEMORY:
        // TODO
        break;
    case PUSH_REGISTER_OR_MEMORY: // fallthrough
    case POP_REGISTER_OR_MEMORY:
        if (info.data_length == 1) {
            displacement_size_string = "BYTE";
        } else if (info.data_length == 2) {
            displacement_size_string = "WORD";
        }
        dst_operand = instruction_decode_effective_address(info, info.instruction_rm);
        disassembly = mnemonic + " " + displacement_size_string  + " " + dst_operand;
        break;
    case XCHG_REGISTER_OR_MEMORY_WITH_REGISTER:
        if (info.instruction_w == 0) {
            displacement_size_string = "BYTE";
        } else if (info.instruction_w == 1) {
            displacement_size_string = "WORD";
        }

		src_operand = instruction_decode_effective_address(info, info.instruction_rm);
		dst_operand = decode_register_name(info.instruction_reg, info.instruction_w);

        disassembly = mnemonic + " " + dst_operand + ", " +  displacement_size_string + "  " + src_operand;
        break;
    case PUSH_SEGMENT_REGISTER: // fallthrough
    case POP_SEGMENT_REGISTER:
        // TODO
        break;
    case XCHG_REGISTER_WITH_ACCUMULATOR:
        src_operand = decode_register_name(info.instruction_reg, info.instruction_w);
        dst_operand = "AX";
        disassembly = mnemonic + " " + dst_operand + ", " + src_operand;
        break;
    case IN_FIXED_PORT: // fallthrough
    case OUT_FIXED_PORT:
        dst_operand = std::to_string(info.instruction_data8);
        disassembly = mnemonic + " " + dst_operand;
        break;
    case IN_VARIABLE_PORT: // fallthrough
    case OUT_VARIABLE_PORT: // fallthrough
    case XLAT: // fallthrough
    case LAHF: // fallthrough
    case SAHF: // fallthrough
    case PUSHF: // fallthrough
    case POPF:
        disassembly = mnemonic;
        break;
    case LEA: // fallthrough
    case LDS: // fallthrough
    case LES:
        src_operand = instruction_decode_effective_address(info, info.instruction_rm);
        dst_operand = decode_register_name(info.instruction_reg, info.instruction_w);

        disassembly = mnemonic + " " + dst_operand + ", " + src_operand;
        break;
    case ARITHMETIC_IMMEDIATE_TO_OR_WITH_REGISTER_OR_MEMORY:
        if (info.instruction_w == 0) {
            displacement_size_string = "BYTE";
        } else if (info.instruction_w == 1) {
            displacement_size_string = "WORD";
        }
        immediate_value = stitch_lower_and_higher_bytes_to_2_byte_value(info.instruction_data_field, info.instruction_data_extended_field); // if data_length is 1, then info.instruction_data_extended_field is zero!

        src_operand =  std::to_string(immediate_value);
        dst_operand = instruction_decode_effective_address(info, info.instruction_rm);

        disassembly = mnemonic + " " + displacement_size_string + " " + dst_operand + ", " + src_operand;
        break;
    case ADD_REGISTER_OR_MEMORY_WITH_REGISTER_TO_EITHER: // fallthrough
    case ADC_REGISTER_OR_MEMORY_WITH_REGISTER_TO_EITHER: // fallthrough
    case SUB_REGISTER_OR_MEMORY_WITH_REGISTER_TO_EITHER: // fallthrough
    case SBB_REGISTER_OR_MEMORY_WITH_REGISTER_TO_EITHER: // fallthrough
    case CMP_REGISTER_OR_MEMORY_WITH_REGISTER_TO_EITHER: // fallthrough
        dst_operand = instruction_decode_effective_address(info, info.instruction_rm);
        src_operand = decode_register_name(info.instruction_reg, info.instruction_w);

        // if the d field is set swap the order of the dst, src registers.
        if (info.instruction_d) {
            std::swap(src_operand, dst_operand);
        }

        disassembly = mnemonic + " " + dst_operand + ", " + src_operand;
        break;
    case ADD_IMMEDIATE_TO_ACCUMULATOR: // fallthrough
    case ADC_IMMEDIATE_TO_ACCUMULATOR: // fallthrough
    case SUB_IMMEDIATE_FROM_ACCUMULATOR: // fallthrough
    case SBB_IMMEDIATE_FROM_ACCUMULATOR: // fallthrough
    case CMP_IMMEDIATE_WITH_ACCUMULATOR:
        assert(info.data_length == 1 || info.data_length == 2);

        if (info.data_length == 1) {
            dst_operand = "AL";
            immediate_value = info.instruction_data_field; // sign extend this here!
        } else {
            dst_operand = "AX";
            immediate_value = stitch_lower_and_higher_bytes_to_2_byte_value(info.instruction_data_field, info.instruction_data_extended_field);
        }
        src_operand = std::to_string(immediate_value);
        disassembly = mnemonic + " " + dst_operand + ", " + src_operand;
        break;
    case RET_JE_OR_JZE: // fallthrough
    case RET_JL_OR_JNGE: // fallthrough
    case RET_JLE_OR_JNG: // fallthrough
    case RET_JB_OR_JNA: // fallthrough
    case RET_JBE_OR_JNA: // fallthrough
    case RET_JP_OR_JPE: // fallthrough
    case RET_JO: // fallthrough
    case RET_JS: // fallthrough
    case RET_JNE_OR_JNZ: // fallthrough
    case RET_JNL_OR_JGE: // fallthrough
    case RET_JNLE_OR_JG: // fallthrough
    case RET_JNB_OR_JAE: // fallthrough
    case RET_JNBE_OR_JA: // fallthrough
    case RET_JNP_OR_JPO: // fallthrough
    case RET_JNO: // fallthrough
    case RET_JNS: // fallthrough
    case RET_LOOP: // fallthrough
    case RET_LOOPZ_OR_LOOPE: // fallthrough
    case RET_LOOPNZ_OR_LOOPNE: // fallthrough
    case RET_JCXZ:
        // +2 is the length of all of these instructions, its a nasm encoding hack for the instruction offset in the RET-type instruction, so we dont have to use labels here.
        immediate_value = info.instruction_ip_inc8 + 2;

        if (immediate_value >= 0) {
            dst_operand = "$+" + std::to_string(immediate_value); // the plus sign is crucial for nasm here!
        } else {
            dst_operand = "$" + std::to_string(immediate_value); // the minus sign is already there in this case
        }
        disassembly = mnemonic + " " + dst_operand;
        break;

    default:
        disassembly = "";
        break;

    }
    return disassembly;
}


std::string Decoder::determine_mnemonic_from_info(const InstructionInfo& info) {
    std::string mnemonic = "UNKNOWN_MNEMONIC";
    switch (info.type) {
    case UNIDENTIFIED:
        break;
    case MOV_REGISTER_OR_MEMORY_TO_OR_FROM_REGISTER: // fallthrough
    case MOV_IMMEDIATE_TO_REGISTER_OR_MEMORY: // fallthrough
    case MOV_IMMEDIATE_TO_REGISTER: // fallthrough
    case MOV_MEMORY_TO_ACCUMULATOR: // fallthrough
    case MOV_ACCUMULATOR_TO_MEMORY: // fallthrough
    case MOV_SEGMENT_REGISTER_TO_REGISTER_OR_MEMORY: // fallthrough
        mnemonic = "MOV";
        break;
    case ARITHMETIC_IMMEDIATE_TO_OR_WITH_REGISTER_OR_MEMORY:
        mnemonic = determine_mnemonic_for_arithmetic_instruction_type_from_reg_field(info);
        break;
    case ADD_REGISTER_OR_MEMORY_WITH_REGISTER_TO_EITHER:  // fallthrough
    case ADD_IMMEDIATE_TO_ACCUMULATOR:
        mnemonic = "ADD";
        break;
    case ADC_REGISTER_OR_MEMORY_WITH_REGISTER_TO_EITHER:  // fallthrough
    case ADC_IMMEDIATE_TO_ACCUMULATOR:
        mnemonic = "ADC";
        break;
    case SUB_REGISTER_OR_MEMORY_WITH_REGISTER_TO_EITHER:  // fallthrough
    case SUB_IMMEDIATE_FROM_ACCUMULATOR:
        mnemonic = "SUB";
        break;
    case SBB_REGISTER_OR_MEMORY_WITH_REGISTER_TO_EITHER:  // fallthrough
    case SBB_IMMEDIATE_FROM_ACCUMULATOR:
        mnemonic = "SBB";
        break;
    case CMP_REGISTER_OR_MEMORY_WITH_REGISTER_TO_EITHER:  // fallthrough
    case CMP_IMMEDIATE_WITH_ACCUMULATOR:
        mnemonic = "CMP";
        break;
    case RET_JE_OR_JZE:
        mnemonic = "JE";
        break;
    case RET_JL_OR_JNGE:
        mnemonic = "JL";
        break;
    case RET_JLE_OR_JNG:
        mnemonic = "JLE";
        break;
    case RET_JB_OR_JNA:
        mnemonic = "JB";
        break;
    case RET_JBE_OR_JNA:
        mnemonic = "JBE";
        break;
    case RET_JP_OR_JPE:
        mnemonic = "JP";
        break;
    case RET_JO:
        mnemonic = "JO";
        break;
    case RET_JS:
        mnemonic = "JS";
        break;
    case RET_JNE_OR_JNZ:
        mnemonic = "JNE";
        break;
    case RET_JNL_OR_JGE:
        mnemonic = "JNL";
        break;
    case RET_JNLE_OR_JG:
        mnemonic = "JNLE";
        break;
    case RET_JNB_OR_JAE:
        mnemonic = "JNB";
        break;
    case RET_JNBE_OR_JA:
        mnemonic = "JNBE";
        break;
    case RET_JNP_OR_JPO:
        mnemonic = "JNP";
        break;
    case RET_JNO:
        mnemonic = "JNO";
        break;
    case RET_JNS:
        mnemonic = "JNS";
        break;
    case RET_LOOP:
        mnemonic = "LOOP";
        break;
    case RET_LOOPZ_OR_LOOPE:
        mnemonic = "LOOPZ";
        break;
    case RET_LOOPNZ_OR_LOOPNE:
        mnemonic = "LOOPNZ";
        break;
    case RET_JCXZ:
        mnemonic = "JCXZ";
        break;
    case PUSH_REGISTER_OR_MEMORY: // fallthrough
    case PUSH_REGISTER: // fallthrough
    case PUSH_SEGMENT_REGISTER:
        mnemonic = "PUSH";
        break;
    case POP_REGISTER_OR_MEMORY: // fallthrough
    case POP_REGISTER: // fallthrough
    case POP_SEGMENT_REGISTER:
        mnemonic = "POP";
        break;
    case XCHG_REGISTER_OR_MEMORY_WITH_REGISTER: // fallthrough
    case XCHG_REGISTER_WITH_ACCUMULATOR:
        mnemonic = "XCHG";
        break;
    case IN_FIXED_PORT: // fallthrough
    case IN_VARIABLE_PORT:
        mnemonic = "IN";
        break;
    case OUT_FIXED_PORT: // fallthrough
    case OUT_VARIABLE_PORT:
        mnemonic = "OUT";
        break;
    case XLAT:
        mnemonic = "XLAT";
        break;
    case LEA:
        mnemonic = "LEA";
        break;
    case LDS:
        mnemonic = "LDS";
        break;
    case LES:
        mnemonic = "LES";
        break;
    case LAHF:
        mnemonic = "LAHF";
        break;
    case SAHF:
        mnemonic = "SAHF";
        break;
    case PUSHF:
        mnemonic = "PUSHF";
        break;
    case POPF:
        mnemonic = "POPF";
        break;
    case InstructionTypeEnumLength: // fallthrough to default
    default:
        break;
    }
    return mnemonic;
}

std::string Decoder::determine_mnemonic_for_arithmetic_instruction_type_from_reg_field(const InstructionInfo& info) {
    assert(info.type == InstructionType::ARITHMETIC_IMMEDIATE_TO_OR_WITH_REGISTER_OR_MEMORY);
    std::string mnemonic = "";

    int reg_value = info.instruction_reg; // use int value so we can use binary literals in the switch statement!
    switch (reg_value) {
    case 0b00000000:
        mnemonic = "ADD";
        break;
    case 0b00000010:
        mnemonic = "ADC";
        break;
    case 0b00000101:
        mnemonic = "SUB";
        break;
    case 0b00000011:
        mnemonic = "SBB";
        break;
    case 0b00000111:
        mnemonic = "CMP";
        break;
    default:
        mnemonic = "UNKNOWN_ARITHMETIC_MNEMONIC_FROM_REG_FIELD";
        break;
    }
    return mnemonic;
}


short Decoder::stitch_lower_and_higher_bytes_to_2_byte_value(char lower, char higher) {
    short lower_byte_as_short = lower; // sign extend cast the char to short
    lower_byte_as_short = lower_byte_as_short & 0x00ff; // dont want sign extension hence we cast the potential higher bits away, which might have been introduced by the cast
    short higher_byte_as_short = higher; // sign extend cast the char to short
    higher_byte_as_short = higher_byte_as_short << 8; // shift it to the higher byte

    // the above addition has the form 0xab00 + 0x00cd (= 0xabcd).
    return higher_byte_as_short + lower_byte_as_short;
}

std::string Decoder::instruction_decode_effective_address(const InstructionInfo& info, char register_decode_value) {
    bool is_direct_address_mode = false;

    std::string register_name = "";
    int mod_value = info.instruction_mod & 0b00000011;
    if (mod_value == 0b11) {
        register_name = decode_register_name(register_decode_value, info.instruction_w);
    } else {
        int rm_value = register_decode_value & 0b00000111;

        switch (rm_value) {
        case 0x00:
            register_name = "[BX + SI";
            break;
        case 0x01:
            register_name = "[BX + DI";
            break;
        case 0x02:
            register_name = "[BP + SI";
            break;
        case 0x03:
            register_name = "[BP + DI";
            break;
        case 0x04:
            register_name = "[SI";
            break;
        case 0x05:
            register_name = "[DI";
            break;
        case 0x06:
            if (mod_value == 0b00) {
                is_direct_address_mode = true;
                register_name = "["; // direct addressing, 16-bit displacement follows
            }
            else {
                register_name = "[BP";
            }
            break;
        case 0x07:
            register_name = "[BX";
            break;
        default:
            break;
        }
        if (info.displacement_length > 0) {
            short displacement_value = 0;
            if (info.displacement_length == 1) {
                displacement_value = info.instruction_disp_lo; // sign extend cast the char to short, this is different than putting the lower byte into a 2 byte value, as  we said we need to sign extend here!
            } else if (info.displacement_length == 2) {
                displacement_value = stitch_lower_and_higher_bytes_to_2_byte_value(info.instruction_disp_lo, info.instruction_disp_hi);
            }


            std::string displacement_value_sign_string = "";
            std::string displacement_value_string = "";

            if (displacement_value == 0) {

            } else if (displacement_value > 0) {
                displacement_value_sign_string = " + ";
                displacement_value_string = std::to_string(displacement_value);

            } else {
                displacement_value_sign_string = " - ";
                displacement_value_string = std::to_string(abs(displacement_value));
            }
            if (is_direct_address_mode) {
                register_name += std::to_string(displacement_value);
            }
            else {
                register_name += displacement_value_sign_string + displacement_value_string;
            }


        }
        register_name += "]";
    }
    return register_name;
}

std::string Decoder::decode_register_name(char register_name_byte, char instruction_w_field) {
    std::string register_name = "";


    // make sure that we only take lower 3 bits.
    int value = register_name_byte & 0b00000111;

    bool instruction_w_is_set = static_cast<bool>(instruction_w_field);
    if (instruction_w_is_set) {
        switch (value) {
        case 0x00:
            register_name = "AX";
            break;
        case 0x01:
            register_name = "CX";
            break;
        case 0x02:
            register_name = "DX";
            break;
        case 0x03:
            register_name = "BX";
            break;
        case 0x04:
            register_name = "SP";
            break;
        case 0x05:
            register_name = "BP";
            break;
        case 0x06:
            register_name = "SI";
            break;
        case 0x07:
            register_name = "DI";
            break;
        default:
            // unreachable.
            break;
        }
    } else {
        switch (value) {
        case 0x00:
            register_name = "AL";
            break;
        case 0x01:
            register_name = "CL";
            break;
        case 0x02:
            register_name = "DL";
            break;
        case 0x03:
            register_name = "BL";
            break;
        case 0x04:
            register_name = "AH";
            break;
        case 0x05:
            register_name = "CH";
            break;
        case 0x06:
            register_name = "DH";
            break;
        case 0x07:
            register_name = "BH";
            break;
        default:
            // unreachable.
            break;
        }
    }

    return register_name;
}


std::string Decoder::get_binary_string(const std::string& contents) {
    std::string result = "";
    for (char c: contents) {
        std::string binary_string = get_binary_string_of_byte(c);

        result += " " + binary_string;
    }

    return result;
}

std::string Decoder::get_binary_string_of_byte(char c) {
    std::string result = "";

    char c0 = c & 0b00000001;
    char c1 = c & 0b00000010;
    char c2 = c & 0b00000100;
    char c3 = c & 0b00001000;
    char c4 = c & 0b00010000;
    char c5 = c & 0b00100000;
    char c6 = c & 0b01000000;
    char c7 = c & 0b10000000;

    if (c7) {
        result += "1";
    } else {
        result += "0";
    }
    if (c6) {
        result += "1";
    } else {
        result += "0";
    }
    if (c5) {
        result += "1";
    } else {
        result += "0";
    }
    if (c4) {
        result += "1";
    } else {
        result += "0";
    }
    if (c3) {
        result += "1";
    } else {
        result += "0";
    }
    if (c2) {
        result += "1";
    } else {
        result += "0";
    }
    if (c1) {
        result += "1";
    } else {
        result += "0";
    }
    if (c0) {
        result += "1";
    } else {
        result += "0";
    }

    return result;
}
