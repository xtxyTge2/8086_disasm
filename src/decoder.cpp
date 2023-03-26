#include "decoder.hpp"

int main(int args, const char** argv) {

	bool use_hard_coded_path = false;
	if (use_hard_coded_path) {
		std::string filename = "C:\\Users\\kala\\code\\computer_enhance_solutions\\computer_enhance\\perfaware\\part1\\listing_0039_more_movs";
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

std::string read_entire_file(const std::string& filename) {
	std::ifstream t(filename);
	std::stringstream file_contents_stream;
	file_contents_stream << t.rdbuf();

	return file_contents_stream.str();
}


std::string parse(const std::string& contents) {
	bool verbose_print = false;

	std::string result = "";
	result.append("bits 16\n");


	const char* contents_data = contents.data();
	std::size_t contents_size = contents.size();
	
	std::size_t current_pos = 0;

	std::array < char, MAX_INSTRUCTION_LENGTH > instruction_data; 
	while(current_pos < contents_size) {
		char current_byte = contents_data[current_pos];

		// get unfilled instruction info struct, containing the opcode and the length of the instruction. 
		InstructionInfo current_info = parse_instruction_type(current_byte);

		bool is_next_byte_needed_for_length = is_next_byte_needed_to_determine_length(current_info);
		char next_byte = 0; // set it to zero
		if(is_next_byte_needed_for_length) {
			// check that we actually can read the next byte!
			if (current_pos + 1 >= contents_size) {
				std::cout << "Error parsing instructions. Attempt to parse instruction, which has a length greater than the input data size.\n";
				return std::string("");
			} 
			next_byte = contents_data[current_pos + 1];
		} 
		// pass in current_byte and next_byte, which is 0 if its not needed to determine the length.
		determine_instruction_length(current_info, current_byte, next_byte);

		// we have determined the length of the instruction at this point and its type.
		assert(current_info.instruction_length > 0);

		// now read that many bytes and fill out the instruction info.
		// first check if we can actually read that many bytes 
		if (current_pos + current_info.instruction_length - 1 >= contents_size) {
			std::cout << "Error parsing instructions. Attempt to parse instruction, which has a length greater than the input data size.\n";
			return std::string("");
		} 

		// collect all the bytes for the current instruction
		instruction_data = {};
		assert(current_info.instruction_length <= instruction_data.size());
		for (int i = 0; i < current_info.instruction_length; i++) {
			instruction_data[i] = contents_data[current_pos + i];
		}

		if (verbose_print) {
			std::cout << "binary instruction data: \n";
			for (int i = 0; i < current_info.instruction_length; i++) {
				std::cout << get_binary_string_of_byte(instruction_data[i]) << " ";
			}
			std::cout << "\n";
		}

		// fill out instruction info
		fill_out_instruction_info(current_info, instruction_data);
		

		std::string instr_result = disassemble_instruction_from_info(current_info);
		result.append(instr_result + "\n");

		if (verbose_print) {
			std::cout << instr_result << "\n";
		}
		// advance current_pos by the length of the just parsed instruction.
		current_pos += current_info.instruction_length;
	}
	

	return result;
}


InstructionInfo parse_instruction_type(char data) {
	InstructionInfo info;
	info.type = InstructionType::UNIDENTIFIED;

	int value = data;
	// check full 8-bits
	switch (value) {
		case 0b10001110:
			info.type = InstructionType::MOV_REGISTER_OR_MEMORY_TO_SEGMENT_REGISTER;
			break;
		case 0b10001100:
			info.type = InstructionType::MOV_SEGMENT_REGISTER_TO_REGISTER_OR_MEMORY;
			break;
		default:
			break;
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
			default:
				break;
		}
	}

	if (info.type == InstructionType::UNIDENTIFIED) {
		// parse instructions, uniquely identified by first six bits, last two bits arbitrary

		// CAREFUL: zero extend the char and consider it as an integer, otherwise we cant use binary literals in the switch statement below, 
		// binary literals are of type int.

		// check 6-bits
		int value_6_bits_masked = data & 0b11111100;
		switch (value_6_bits_masked) {
			case 0b10001000: // MOV_REGISTER_OR_MEMORY_TO_OR_FROM_REGISTER
				info.type = InstructionType::MOV_REGISTER_OR_MEMORY_TO_OR_FROM_REGISTER;
				break;
			default:
				break;
		}
	}

	if (info.type == InstructionType::UNIDENTIFIED) {
		// check 5-bits
		int value_5_bits_masked = value & 0b11111000;
		switch (value_5_bits_masked) {
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

bool is_next_byte_needed_to_determine_length(InstructionInfo& info) {
	bool is_needed = false;
	switch (info.type) {
		case MOV_REGISTER_OR_MEMORY_TO_OR_FROM_REGISTER:  // fallthrough
		case MOV_IMMEDIATE_TO_REGISTER_OR_MEMORY: // fallthrough
		case MOV_IMMEDIATE_TO_REGISTER: // fallthrough
		case MOV_MEMORY_TO_ACCUMULATOR: // fallthrough
		case MOV_ACCUMULATOR_TO_MEMORY: // fallthrough
		case MOV_REGISTER_OR_MEMORY_TO_SEGMENT_REGISTER: // fallthrough
		case MOV_SEGMENT_REGISTER_TO_REGISTER_OR_MEMORY: // fallthrough
			is_needed = true;
			break;
		case InstructionTypeEnumLength: // fallthrough to default
		case UNIDENTIFIED: // fallthrough to default
		default:
			break;
	}
	return is_needed;
}

unsigned int determine_displacement_length_from_second_byte(char data) {
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


void determine_instruction_length(InstructionInfo& info, char first_byte, char second_byte) {

	int w_field_value = 0;
	switch (info.type) {
		case MOV_REGISTER_OR_MEMORY_TO_OR_FROM_REGISTER:
			info.base_length = 2;
			info.displacement_length = determine_displacement_length_from_second_byte(second_byte);
			break;
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
		case MOV_MEMORY_TO_ACCUMULATOR:
			info.base_length = 1;
			info.address_length = 2;
			break;
		case MOV_ACCUMULATOR_TO_MEMORY:
			info.base_length = 1;
			info.address_length = 2;
			break;
		case MOV_REGISTER_OR_MEMORY_TO_SEGMENT_REGISTER:
			info.base_length = 2; 
			info.displacement_length = determine_displacement_length_from_second_byte(second_byte);
			break;
		case MOV_SEGMENT_REGISTER_TO_REGISTER_OR_MEMORY:
			info.base_length = 2; 
			info.displacement_length = determine_displacement_length_from_second_byte(second_byte);
			break;
		case InstructionTypeEnumLength: // fallthrough to default
		case UNIDENTIFIED: // fallthrough to default
		default:
			break;
	}
	info.instruction_length = info.base_length + info.displacement_length + info.data_length + info.address_length;
}

void fill_out_instruction_info(InstructionInfo& info, std::array < char, MAX_INSTRUCTION_LENGTH > & instruction_data) {
	switch (info.type) {
		case InstructionType::MOV_REGISTER_OR_MEMORY_TO_OR_FROM_REGISTER:
			assert(info.base_length == 2);
			assert(info.displacement_length == 0 || info.displacement_length == 1 || info.displacement_length == 2);
			assert(info.data_length == 0 && info.address_length == 0);
			assert(info.instruction_length == info.base_length + info.displacement_length + info.data_length + info.address_length);

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
			assert(info.instruction_length == info.base_length + info.displacement_length + info.data_length + info.address_length);

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
			assert(info.instruction_length == info.base_length + info.displacement_length + info.data_length + info.address_length);

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
			assert(info.instruction_length == info.base_length + info.displacement_length + info.data_length + info.address_length);


			info.instruction_w = (instruction_data[0] & 0b00001000) >> 3;
			info.instruction_address_lo = instruction_data[1];
			info.instruction_address_hi = instruction_data[2];
			break;
		case MOV_REGISTER_OR_MEMORY_TO_SEGMENT_REGISTER: // fallthrough
		case MOV_SEGMENT_REGISTER_TO_REGISTER_OR_MEMORY:
			assert(info.base_length == 2);
			assert(info.displacement_length == 0 || info.displacement_length == 1 || info.displacement_length == 2);
			assert(info.address_length == 0 && info.data_length == 0);
			assert(info.instruction_length == info.base_length + info.displacement_length + info.data_length + info.address_length);

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
		case InstructionTypeEnumLength: // fallthrough to default
		case UNIDENTIFIED: // fallthrough to default
		default:
			break;
	}
}

std::string parse_instruction_infos(const std::vector < InstructionInfo > & instruction_infos) {
	std::string result;
	result.append("bits 16\n");

	for (const InstructionInfo& info: instruction_infos) {
		std::string instr_result = disassemble_instruction_from_info(info);
		result += instr_result + "\n";
	}
	return result;
}

std::string disassemble_instruction_from_info(const InstructionInfo& info) {
	std::string disassembly = "";
	
	std::string mnemonic = "";
	std::string src_operand = "";
	std::string dst_operand = "";
	std::string immediate_size_string = "";

	short immediate_value = 0; 
	short address_value = 0;

	switch (info.type) {
		case MOV_REGISTER_OR_MEMORY_TO_OR_FROM_REGISTER:
			mnemonic = "MOV";
			dst_operand = instruction_decode_effective_address(info, info.instruction_rm);
			src_operand = decode_register_name(info.instruction_reg, info.instruction_w);

			// if the d field is set swap the order of the dst, src registers.
			if (info.instruction_d) {
				std::swap(src_operand, dst_operand);
			}


			disassembly = mnemonic + " " + dst_operand + ", " + src_operand;
			break;
		case MOV_IMMEDIATE_TO_REGISTER_OR_MEMORY:
			mnemonic = "MOV";
			if (info.data_length == 1) {
				immediate_size_string = "BYTE";
			} else if (info.data_length == 2) {
				immediate_size_string = "WORD";
			}
			immediate_value = stitch_lower_and_higher_bytes_to_2_byte_value(info.instruction_data_field, info.instruction_data_extended_field); // if data_length is 1, then info.instruction_data_extended_field is zero!

			src_operand =  std::to_string(immediate_value);
			dst_operand = instruction_decode_effective_address(info, info.instruction_rm);

			disassembly = mnemonic + " " + dst_operand + ", " + immediate_size_string + " " + src_operand;
			break;
		case MOV_IMMEDIATE_TO_REGISTER:
			mnemonic = "MOV";

			if (info.data_length == 1) {
				immediate_size_string = "BYTE";
				//immediate_value = info.instruction_data_field; // sign extend cast the char to short
			} else if (info.data_length == 2) {
				immediate_size_string = "WORD";
			}
			immediate_value = stitch_lower_and_higher_bytes_to_2_byte_value(info.instruction_data_field, info.instruction_data_extended_field); // if data_length is 1, then info.instruction_data_extended_field is zero!

			src_operand = std::to_string(immediate_value);
			dst_operand = decode_register_name(info.instruction_reg, info.instruction_w);

			disassembly = mnemonic + " " + dst_operand + ", " + immediate_size_string + " " + src_operand;
			break;
		case MOV_MEMORY_TO_ACCUMULATOR:
			mnemonic = "MOV";
			assert(info.address_length == 2);

			address_value = stitch_lower_and_higher_bytes_to_2_byte_value(info.instruction_address_lo, info.instruction_address_hi);

			src_operand = "[" + std::to_string(address_value) + "]";
			dst_operand = "AX";

			disassembly = mnemonic + " " + dst_operand + ", " + src_operand;
			break;
		case MOV_ACCUMULATOR_TO_MEMORY:
			mnemonic = "MOV";
			assert(info.address_length == 2);

			address_value = stitch_lower_and_higher_bytes_to_2_byte_value(info.instruction_address_lo, info.instruction_address_hi);
			
			src_operand = "AX";
			dst_operand = "[" + std::to_string(address_value) + "]";

			disassembly = mnemonic + " " + dst_operand + ", " + src_operand;
			break;
		case MOV_REGISTER_OR_MEMORY_TO_SEGMENT_REGISTER:
			break;
		case MOV_SEGMENT_REGISTER_TO_REGISTER_OR_MEMORY:
			break;
		default:
			disassembly = "";
			break;
	}
	return disassembly;
}

short stitch_lower_and_higher_bytes_to_2_byte_value(char lower, char higher) {
	short lower_byte_as_short = lower; // sign extend cast the char to short
	lower_byte_as_short = lower_byte_as_short & 0x00ff; // dont want sign extension hence we cast the potential higher bits away, which might have been introduced by the cast
	short higher_byte_as_short = higher; // sign extend cast the char to short
	higher_byte_as_short = higher_byte_as_short << 8; // shift it to the higher byte

	// the above addition has the form 0xab00 + 0x00cd (= 0xabcd).
	return higher_byte_as_short + lower_byte_as_short;
}

std::string instruction_decode_effective_address(const InstructionInfo& info, char register_decode_value) {
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
			short displacement_lower_byte_as_short = 0;
			short displacement_higher_byte_as_short = 0;
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

std::string decode_register_name(char register_name_byte, char instruction_w_field) {
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


std::string get_binary_string(const std::string& contents) {
	std::string result = "";
	for (char c: contents) {
		std::string binary_string = get_binary_string_of_byte(c);

		result += " " + binary_string;
	}

	return result;
}

std::string get_binary_string_of_byte(char c) {
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