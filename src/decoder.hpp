#include <iostream>
#include <fstream>
#include <sstream>
#include <array>
#include <vector>
#include <cassert>


int main(int argc, const char** argv);
std::string parse(const std::string& contents);
std::string read_entire_file(const std::string& filename);


enum InstructionType {
	UNIDENTIFIED,

	// MOV
	MOV_REGISTER_OR_MEMORY_TO_OR_FROM_REGISTER,
	MOV_IMMEDIATE_TO_REGISTER_OR_MEMORY,
	MOV_IMMEDIATE_TO_REGISTER,
	MOV_MEMORY_TO_ACCUMULATOR,
	MOV_ACCUMULATOR_TO_MEMORY,
	MOV_REGISTER_OR_MEMORY_TO_SEGMENT_REGISTER,
	MOV_SEGMENT_REGISTER_TO_REGISTER_OR_MEMORY,
	
	// PUSH
	PUSH_REGISTER_OR_MEMORY,
	PUSH_REGISTER,
	PUSH_SEGMENT_REGISTER,

	// POP
	POP_REGISTER_OR_MEMORY,
	POP_REGISTER,
	POP_SEGMENT_REGISTER,

	// XCHG -- EXCHANGE
	XCHG_REGISTER_OR_MEMORY_WITH_REGISTER,
	XCHG_REGISTER_WITH_ACCUMULATOR,

	// IN
	IN_FIXED_PORT,
	IN_VARIABLE_PORT,

	// OUT
	OUT_FIXED_PORT,
	OUT_VARIABLE_PORT,
	XLAT,
	LEA,
	LDS,
	LES,
	LAHF,
	SAHF,
	PUSHF,
	POPF,

	// GENERAL ARITHMETIC TYPE, WHICH SAVES US TO REPEAT THE SAME PARSING FOR ADD, ADC, SUB, SBB, CMP. The mnemonic is encoded in the reg field.
	ARITHMETIC_IMMEDIATE_TO_OR_WITH_REGISTER_OR_MEMORY,
	
	// ADD 
	ADD_REGISTER_OR_MEMORY_WITH_REGISTER_TO_EITHER,
	ADD_IMMEDIATE_TO_ACCUMULATOR,

	// ADC
	ADC_REGISTER_OR_MEMORY_WITH_REGISTER_TO_EITHER,
	ADC_IMMEDIATE_TO_ACCUMULATOR,

	// SUB
	SUB_REGISTER_OR_MEMORY_WITH_REGISTER_TO_EITHER,
	SUB_IMMEDIATE_FROM_ACCUMULATOR,

	// SBB
	SBB_REGISTER_OR_MEMORY_WITH_REGISTER_TO_EITHER,
	SBB_IMMEDIATE_FROM_ACCUMULATOR,

	// CMP
	CMP_REGISTER_OR_MEMORY_WITH_REGISTER_TO_EITHER,
	CMP_IMMEDIATE_WITH_ACCUMULATOR,

	// RET
	RET_JE_OR_JZE,
	RET_JL_OR_JNGE,
	RET_JLE_OR_JNG,
	RET_JB_OR_JNA,
	RET_JBE_OR_JNA,
	RET_JP_OR_JPE,
	RET_JO,
	RET_JS,
	RET_JNE_OR_JNZ,
	RET_JNL_OR_JGE,
	RET_JNLE_OR_JG,
	RET_JNB_OR_JAE,
	RET_JNBE_OR_JA,
	RET_JNP_OR_JPO,
	RET_JNO,
	RET_JNS,
	RET_LOOP,
	RET_LOOPZ_OR_LOOPE,
	RET_LOOPNZ_OR_LOOPNE,
	RET_JCXZ,


	InstructionTypeEnumLength
};

constexpr static unsigned int MAX_INSTRUCTION_LENGTH = 6;
struct InstructionInfo{
	InstructionType type = InstructionType::UNIDENTIFIED;

	unsigned int instruction_length = 0; // instruction_length = base_length + displacement_length + data_length + address_length + ip_inc8_length + data8_length
	unsigned int base_length = 0;
	unsigned int displacement_length = 0; // either 0, 1 or 2. 0 means no displacement, 1 means just disp-lo is set, 2 means disp-lo and disp-hi are set.
	unsigned int data_length = 0;
	unsigned int address_length = 0;
	unsigned int ip_inc8_length = 0;
	unsigned int data8_length = 0;

	char instruction_d = 0;
	char instruction_s = 0;
	char instruction_w = 0;
	char instruction_v = 0;
	char instruction_mod = 0;
	char instruction_reg = 0;
	char instruction_rm = 0;
	char instruction_sr = 0;
	
	char instruction_disp_lo = 0;
	char instruction_disp_hi = 0;

	char instruction_data_field = 0;
	char instruction_data_extended_field = 0;

	char instruction_address_lo = 0;
	char instruction_address_hi = 0;

	char instruction_ip_inc8 = 0;

	char instruction_data8 = 0;
};

struct Instruction {
	std::string mnemonic = "";
	std::string src_operand = "";
	std::string dst_operand = "";
};



InstructionInfo parse_instruction_type(char data);
void determine_instruction_length(InstructionInfo& info, char first_byte, char second_byte);


void fill_out_instruction_info(InstructionInfo& info, std::array < char, MAX_INSTRUCTION_LENGTH > & instruction_data);


std::string parse_instruction_infos(const std::vector < InstructionInfo > & instruction_infos);
std::string disassemble_instruction_from_info(const InstructionInfo& info);
std::string decode_register_name(char instruction_rm, char instruction_w);
short stitch_lower_and_higher_bytes_to_2_byte_value(char lower, char higher);

std::string get_binary_string(const std::string& contents);
std::string get_binary_string_of_byte(char c);


bool is_next_byte_needed_to_determine_length(InstructionInfo& info);
unsigned int determine_displacement_length_from_second_byte(char data);

std::string determine_mnemonic_from_info(const InstructionInfo& info);
std::string determine_mnemonic_for_arithmetic_instruction_type_from_reg_field(const InstructionInfo& info);
std::string instruction_decode_effective_address(const InstructionInfo& info, char register_decode_value);