#include <stdlib.h>
#include <stdio.h>

#define Nb 4 // Number of columns (32-bit words) comprising the state. For this standard, Nb = 4.
#define Nk 4 // Number of 32-bit words comprising the Cipher Key. For this standard, Nk = 4, 6 or 8.
#define Nr 10
#include <memory>
#include <iostream>

using namespace std;

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;

typedef struct euclid
{
	short a;
	short s;
	short t;
}euclid;

#pragma region helper
void validate_string(char** input)
{
	int input_length = strlen(*input);
	int rest = 0;

	if (Nk == 4)
		rest = input_length % 16;
	else if (Nk == 6)
		rest = input_length % 24;
	else
		rest = input_length % 32;

	// When the length of the input string is not a multiple of 16 (128 Bit), 24 (192 Bit) or 32 (256 Bit)..
	if (rest != 0)
	{
		// then expand the size of the string to the appropriate length
		char* validated_input = (char*)malloc(input_length + rest + 1);
		// copy the original value of the input in our new string with the correct size
		strcpy(validated_input, *input);
		// fill it up with zeroes
		validated_input[input_length + rest] = 0;
		// set the input to our string with the correct size
		*input = validated_input;
	}
}

u8 calc_msb_index(u16 number)
{
	u8 result = 0;

	while (number) {
		result++;
		number >>= 1;
	}

	return result;
}

u8 xtime(u8 byte)
{
	// Check the most significant bit before shifting
	int xor = 0;
	if (byte & 0x80)
		xor = 1;
	// Shift the byte
	byte = byte << 1;
	// XOR when most significant bit before shifting was 1
	if (xor)
		byte ^= 0x1b;

	return byte;
}

u8 multiply(u8 byte, u8 factor)
{
	u8 result = 0;

	for (int i = 1; i <= 0x80; i *= 2, byte = xtime(byte)) {
		if (factor & i)
			result ^= byte;
	}

	return result;
}

u8 calc_inverse(u8 byte)
{
	if (!byte)
		return 0;

	euclid* left = (euclid*)malloc(sizeof(euclid));
	euclid* right = (euclid*)malloc(sizeof(euclid));

	left->a = 0x11b, left->s = 1, left->t = 0;
	right->a = byte, right->s = 0, right->t = 1;



	while (right->a != 1) {
		u8 r = calc_msb_index(left->a) - calc_msb_index(right->a);

		left->a ^= right->a << r;
		left->t ^= right->t << r;

		if (right->a > left->a) {
			euclid* temp = left;
			left = right;
			right = temp;
		}
	}

	return right->t;
}

u8 affine_transformation(u8 byte)
{
	// Initialize matrix
	u8 matrix[8][8] = {
		{ 1, 0, 0, 0, 1, 1, 1, 1 },
		{ 1, 1, 0, 0, 0, 1, 1, 1 },
		{ 1, 1, 1, 0, 0, 0, 1, 1 },
		{ 1, 1, 1, 1, 0, 0, 0, 1 },
		{ 1, 1, 1, 1, 1, 0, 0, 0 },
		{ 0, 1, 1, 1, 1, 1, 0, 0 },
		{ 0, 0, 1, 1, 1, 1, 1, 0 },
		{ 0, 0, 0, 1, 1, 1, 1, 1 }
	};

	// Initialize bit vector (factor)
	u8 bits[8];
	for (int i = 0; i < 8; ++i) {
		bits[i] = byte & (1 << i) ? 1 : 0;
	}

	// Calc result bit vector
	u8 result[8];
	for (int i = 0; i < 8; ++i) {
		result[i] = 0;
		for (int j = 0; j < 8; ++j) {
			result[i] ^= multiply(matrix[i][j], bits[j]);
		}
	}

	// Convert result bit vector into byte
	byte = 0;
	for (int i = 0; i < 8; ++i) {
		if (result[i])
			byte |= 1 << i;
	}

	// Add 0x63
	byte ^= 0x63;

	// return result
	return byte;
}

u8 inv_affine_transformation(u8 byte)
{
	// Initialize matrix
	u8 matrix[8][8] = {
		{ 0, 0, 1, 0, 0, 1, 0, 1 },
		{ 1, 0, 0, 1, 0, 0, 1, 0 },
		{ 0, 1, 0, 0, 1, 0, 0, 1 },
		{ 1, 0, 1, 0, 0, 1, 0, 0 },
		{ 0, 1, 0, 1, 0, 0, 1, 0 },
		{ 0, 0, 1, 0, 1, 0, 0, 1 },
		{ 1, 0, 0, 1, 0, 1, 0, 0 },
		{ 0, 1, 0, 0, 1, 0, 1, 0 }
	};

	// Initialize bit vector (factor)
	u8 bits[8];
	for (int i = 0; i < 8; ++i) {
		bits[i] = byte & (1 << i) ? 1 : 0;
	}

	// Calc result bit vector
	u8 result[8];
	for (int i = 0; i < 8; ++i) {
		result[i] = 0;
		for (int j = 0; j < 8; ++j) {
			result[i] ^= multiply(matrix[i][j], bits[j]);
		}
	}

	// Convert result bit vector into byte
	byte = 0;
	for (int i = 0; i < 8; ++i) {
		if (result[i])
			byte |= 1 << i;
	}

	// Add 0x63
	byte ^= 0x05;

	// return result
	return byte;
}

u32 rcon(u8 in)
{
	unsigned char c = 1;
	if (in == 0)
		return 0;
	while (in != 1) {
		c = xtime(c);
		in--;
	}
	return c << 24;

}
#pragma endregion helper

void AddRoundKey(u8 (*state)[4][Nb], u32 round_key[4])
{
	for (int i = 0; i < Nb; ++i)
	{
		(*state)[0][i] ^= round_key[i] >> 24;
		(*state)[1][i] ^= round_key[i] >> 16;
		(*state)[2][i] ^= round_key[i] >> 8;
		(*state)[3][i] ^= round_key[i];
	}
}

void SubBytes(u8 (*state)[4][Nb])
{
	for (int i = 0; i < 4; ++i) {
		for (int j = 0; j < Nb; ++j) {
			(*state)[i][j] = calc_inverse((*state)[i][j]);
			(*state)[i][j] = affine_transformation((*state)[i][j]);
		}
	}
}

void ShiftRows(u8 (*state)[4][Nb])
{
	u8 temp[4][Nb];

	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			temp[i][(j + ((((-i) % Nb) + Nb) % Nb) % Nb) % Nb] = (*state)[i][j];
		}
	}

	memcpy(state, &temp, 4 * Nb);
}

void MixColumns(u8 (*state)[4][Nb])
{
	for (int i = 0; i < 4; ++i) {
		u8 temp[4];

		for (int j = 0; j < Nb; ++j) {
			temp[j] = (*state)[j][i];
		}

		(*state)[0][i] = (multiply(0x02, temp[0]) ^ (multiply(0x03, temp[1]) ^ temp[2] ^ temp[3]));
		(*state)[1][i] = (temp[0] ^ multiply(0x02, temp[1]) ^ multiply(0x03, temp[2]) ^ temp[3]);
		(*state)[2][i] = (temp[0] ^ temp[1] ^ multiply(0x02, temp[2]) ^ multiply(0x03, temp[3]));
		(*state)[3][i] = (multiply(0x03, temp[0]) ^ temp[1] ^ temp[2] ^ multiply(0x02, temp[3]));
	}
}

void InvSubBytes(u8(*state)[4][Nb])
{
	for (int i = 0; i < 4; ++i) {
		for (int j = 0; j < Nb; ++j) {
			(*state)[i][j] = inv_affine_transformation((*state)[i][j]);
			(*state)[i][j] = calc_inverse((*state)[i][j]);
		}
	}
}

void InvShiftRows(u8(*state)[4][Nb])
{
	u8 temp[4][Nb];

	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			temp[i][(j + i) % Nb] = (*state)[i][j];
		}
	}

	memcpy(state, &temp, 4 * Nb);
}

void InvMixColumns(u8(*state)[4][Nb])
{
	for (int i = 0; i < 4; ++i) {
		u8 temp[4];

		for (int j = 0; j < Nb; ++j) {
			temp[j] = (*state)[j][i];
		}

		(*state)[0][i] = (multiply(0x0e, temp[0]) ^ multiply(0x0b, temp[1]) ^ multiply(0x0d, temp[2]) ^ multiply(0x09, temp[3]));
		(*state)[1][i] = (multiply(0x09, temp[0]) ^ multiply(0x0e, temp[1]) ^ multiply(0x0b, temp[2]) ^ multiply(0x0d, temp[3]));
		(*state)[2][i] = (multiply(0x0d, temp[0]) ^ multiply(0x09, temp[1]) ^ multiply(0x0e, temp[2]) ^ multiply(0x0b, temp[3]));
		(*state)[3][i] = (multiply(0x0b, temp[0]) ^ multiply(0x0d, temp[1]) ^ multiply(0x09, temp[2]) ^ multiply(0x0e, temp[3]));
	}
}

void Cipher(u8 in[4 * Nb], u8 (*out)[4 * Nb], u32 w[Nb * (Nr + 1)])
{
	// Copy input into the state
	u8 state[4][Nb];

	for (int i = 0; i < 4; ++i)
	{
		u8 temp[Nb] = { in[i], in[i + 4], in[i + 8], in[i + 12]};
		memcpy(&state[i], temp, 4);
	}

	AddRoundKey(&state, &(w[0]));

	for (int round = 1; round <= Nr - 1; round++) {
		SubBytes(&state);
		ShiftRows(&state);
		MixColumns(&state);
		AddRoundKey(&state, &(w[round*Nb]));
	}

	SubBytes(&state);
	ShiftRows(&state);
	AddRoundKey(&state, &(w[Nr*Nb]));

	// Copy state into output
	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < Nb; j++)
		{
			(*out)[i * 4 + j] = state[j][i];
		}
	}
}

void InvCipher(u8 in[4 * Nb], u8(*out)[4 * Nb], u32 w[Nb * (Nr + 1)])
{
	// Copy input into the state
	u8 state[4][Nb];

	for (int i = 0; i < 4; ++i) {
		u8 temp[Nb] = { in[i], in[i + 4], in[i + 8], in[i + 12] };
		memcpy(&state[i], temp, 4);
	}

	AddRoundKey(&state, &(w[Nr * Nb]));

	for (int round = Nr - 1; round > 0; round--) {
		InvShiftRows(&state);
		InvSubBytes(&state);
		AddRoundKey(&state, &(w[round * Nb]));
		InvMixColumns(&state);
	}

	InvShiftRows(&state);
	InvSubBytes(&state);
	AddRoundKey(&state, &(w[0]));

	// Copy state into output
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < Nb; j++) {
			(*out)[i * 4 + j] = state[j][i];
		}
	}
}

u32 SubWord(u32 word)
{
	u8 temp[4] = { (word >> 24), (word >> 16), (word >> 8), (word & 0x000000FF) };

	for (int i = 0; i < 4; ++i) {
		temp[i] = calc_inverse(temp[i]);
		temp[i] = affine_transformation(temp[i]);
	}

	return ((temp[0] << 24) | (temp[1] << 16) | (temp[2] << 8) | (temp[3]));
}

u32 RotWord(u32 word)
{
	u8 firstbits = word >> 24;
	word <<= 8;
	word |= firstbits;
	return word;
}

void KeyExpansion(u8 key[4 * Nk], u32(*w)[Nb*(Nr + 1)])
{
	u32 temp_word = 0;

	for (int i = 0; i < Nk; ++i) {
		temp_word = (key[4 * i] << 24) | (key[4 * i + 1] << 16) | (key[4 * i + 2] << 8) | (key[4 * i + 3]);
		(*w)[i] = temp_word;
	}

	for (int i = Nk; i < Nb * (Nr + 1); ++i) {
		temp_word = (*w)[i - 1];
		if (i % Nk == 0) {
			temp_word = (SubWord(RotWord(temp_word)) ^ rcon(i / Nk));
		}
		else if (Nk > 6 && i % Nk == 4)
			temp_word = SubWord(temp_word);

		(*w)[i] = (*w)[i - Nk] ^ temp_word;
	}
}

void encrypt(char *input, char* key, char *output)
{
	for (; *input; input+=4 * Nb, output += 16)
	{
		// Copy to u8 array (type mismatch) TODO: Fix this shit
		u8 text[4 * Nb];
		u8 keyu8[4 * Nb];
		memcpy(text, input, 4 * Nb);
		memcpy(keyu8, key, 4 * Nb);

		// encrypt 16 bytes of input
		u8 ciphertext[4 * Nb];
		u32 key_schedule[Nb * (Nr + 1)];
		KeyExpansion(keyu8, &key_schedule);
		Cipher(text, &ciphertext, key_schedule);

		// append encrypted 16 bytes to output
		memcpy(output, ciphertext, 4 * Nb);
	}

	// add terminating zero to output string
	*output = 0;
}

void decrypt(char *input, char* key, char *output)
{
	for (; *input; input += 4 * Nb, output += 16) {
		// Copy to u8 array (type mismatch) TODO: Fix this shit
		u8 text[4 * Nb];
		u8 keyu8[4 * Nb];
		memcpy(text, input, 4 * Nb);
		memcpy(keyu8, key, 4 * Nb);

		// decrypt 16 bytes of input
		u8 ciphertext[4 * Nb];
		u32 key_schedule[Nb * (Nr + 1)];
		KeyExpansion(keyu8, &key_schedule);
		InvCipher(text, &ciphertext, key_schedule);

		// append encrypted 16 bytes to output
		memcpy(output, ciphertext, 4 * Nb);
	}

	// add terminating zero to output string
	*output = 0;
}

void main()
{
	char *text = "Hallo, das ist ein Test!";
	char *key = "Mein Passwort!!!";

	char *ciphertext = (char*) malloc(strlen(text) + 1);
	char *decrypted_text = (char*) malloc(strlen(text) + 1);
	validate_string(&text);
	validate_string(&ciphertext);
	cout << "Encrypting '" << text << "' with key '" << key << "'.." << endl;
	encrypt(text, key, ciphertext);

	validate_string(&decrypted_text);
	cout << "Decrypting.." << endl;
	decrypt(ciphertext, key, decrypted_text);

	if (!strcmp(text, decrypted_text))
		cout << "Success!" << endl;
	else
		cout << "Something went wrong..";
	
	free(ciphertext);
	free(decrypted_text);
}