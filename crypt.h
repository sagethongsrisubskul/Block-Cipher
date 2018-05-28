union block64{
        uint64_t block;
	uint32_t half[2];
        uint16_t fourth[4];
	uint8_t eighth[8];

};

uint8_t char_to_hex(char);

char hex_to_char(uint8_t);

uint64_t textblock_to_hex(char*);

uint64_t plaintext_to_hex(char*);

void write_hex_as_chars(FILE*,uint64_t);

void write_hex_as_plaintext(FILE*,uint64_t);

uint64_t whiten(uint64_t,uint64_t);

uint16_t g(uint16_t,int,int);

uint8_t k(int);

void set_key(uint64_t a);

uint16_t get_ftable(uint8_t);

uint32_t f(uint16_t,uint16_t,int);

uint16_t concat_to_16(uint8_t,uint8_t);

uint32_t concat_to_32(uint16_t,uint16_t);

uint16_t get_f(int32_t,int);
