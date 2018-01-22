#include "sha.h"
#include "chunk.h"
#include <ctype.h>
#include <assert.h>
#include <stdlib.h> // for malloc
#include <string.h> // for memset
#include <stdio.h>
#include "utility.h"

/**
 * fp -- the file pointer you want to chunkify.
 * chunk_hashes -- The chunks are stored at this locations.
 */
/* Returns the number of chunks created */
int make_chunks(FILE *fp, uint8_t *chunk_hashes[]) {
	//allocate a big buffer for the chunks from the file.
	uint8_t *buffer = (uint8_t *) malloc(BT_CHUNK_SIZE);
	int numchunks = 0;
	int numbytes = 0;

	// read the bytes from the file and fill in the chunk_hashes
	while((numbytes = fread(buffer, sizeof(uint8_t), BT_CHUNK_SIZE, fp)) > 0 ) {
		shahash(buffer, numbytes, chunk_hashes[numchunks++]);
	}

	return numchunks;
}

/**
 * str -- is the data you want to hash
 * len -- the length of the data you want to hash.
 * hash -- the target where the function stores the hash. The length of the
 *         array should be SHA1_HASH_SIZE.
 */
void shahash(uint8_t *str, int len, uint8_t *hash) {
	SHA1Context sha;

	// init the context.
	SHA1Init(&sha);

	// update the hashes.
	// this can be used multiple times to add more
	// data to hash.
	SHA1Update(&sha, str, len);

	// finalize the hash and store in the target.
	SHA1Final(&sha, hash);

	// A little bit of paranoia.
	memset(&sha, 0, sizeof(sha));
}

/**
 * converts the binary char string str to ascii format. the length of 
 * ascii should be 2 times that of str
 */
void binary2hex(uint8_t *buf, int len, char *hex) {
	int i=0;
	for(i=0;i<len;i++) {
		sprintf(hex+(i*2), "%.2x", buf[i]);
	}
	hex[len*2] = 0;
}
  
/**
 *Ascii to hex conversion routine
 */
static uint8_t _hex2binary(char hex)
{
     hex = toupper(hex);
     uint8_t c = ((hex <= '9') ? (hex - '0') : (hex - ('A' - 0x0A)));
     return c;
}

/**
 * converts the ascii character string in "ascii" to binary string in "buf"
 * the length of buf should be atleast len / 2
 */
void hex2binary(char *hex, int len, uint8_t*buf) {
	int i = 0;
	for(i=0;i<len;i+=2) {
		buf[i/2] = 	_hex2binary(hex[i]) << 4 
				| _hex2binary(hex[i+1]);
	}
}

/**
 * read chunk hashes in the file into the vector
 * @param filename a file contains chunk hashes
 * @param v vector stores the hashes in the file
 * @return
 */
void read_chunk(char *filename, vector *v){
	FILE *f = Fopen(filename, "r");
	char *token, *line = NULL;
	size_t line_len;

	while(getline(&line, &line_len, f) != -1){
		token = strtok(line, " ");
		if (isdigit(token[0])){
			token = strtok(NULL, " ");
			if (token[strlen(token) -1] == '\n'){
				token[strlen(token) -1] = '\0';
			}
			vec_add(v, token);
		}else{
			/* skip the current line */
			fprintf(stdout, "Comment line in chunk file\n");
		}
		free(line); // memory is dynamically allocated in getline
		line = NULL;
		line_len = 0;
	}
	return;
}

/**
 * return the chunk id of the given the input chunk hash
 * @param chunk_hash
 * @param hash_chunk_file
 * @return
 */
size_t find_chunk_idx_from_hash(char *chunk_hash, char *hash_chunk_file){
	FILE *f;
	char *line, line_backup[BT_FILENAME_LEN], *t;
	size_t line_len = 0;
	int idx, chunk_idx;

	f = Fopen(hash_chunk_file, "r");
	while (getline(&line, &line_len, f) != -1) {
		memset(line_backup, 0, BT_FILENAME_LEN);
		strcpy(line_backup, line);
		t = strtok(line_backup, " ");
		if (!isdigit(*t)) { /* the first line */
			t = strtok(NULL, " ");
			t = strtok(NULL, " "); /* there is a remaining hash line */
			if (t != NULL) {
				idx = *(int *) t;
				t = strtok(NULL, " ");
				if (!strcmp(t, chunk_hash) || strstr(t, chunk_hash) != NULL) {
					chunk_idx = idx;
					free(line);
					break;
				}
			}
		} else { /* chunk hash line */
			idx = atoi(t);
			t = strtok(NULL, " ");
			if (!strcmp(t, chunk_hash) || strstr(t, chunk_hash) != NULL) {
				chunk_idx = idx;
				free(line);
				break;
			}
		}
		free(line);
		line = NULL;
		line_len = 0;
	}
	return chunk_idx;
}

/**
 * based on input chunk, and chunk length, calculate the hash
 * @param chunk
 * @param size
 * @return
 */
char *get_chunk_hash(char *chunk, size_t size){
	uint8_t *hash;
	char *chunk_hash;
	if ((hash = malloc(SHA1_HASH_SIZE * sizeof(uint8_t))) == NULL){
		fprintf(stderr, "Failed to allocate memory\n");
		exit(-1);
	}
	if ((chunk_hash = malloc(SHA1_HASH_SIZE * 2 + 1)) == NULL){
		fprintf(stderr, "Failed to allocate memory\n");
		exit(-1);
	}
        fprintf(stdout, "calculating chunk hash for a chunk of size %d\n", size);
	shahash((uint8_t*)chunk, size, hash);
	hex2ascii(hash, SHA1_HASH_SIZE, chunk_hash);
        fprintf(stdout, "the ascii of calculated hash is %s\n", chunk_hash);
	free(hash);
	return chunk_hash;
}

/**
 * move the file cursor to the chunk pointed to by chunk_idx
 * @param f
 * @param chunk_idx
 */
void seek_to_chunk_pos(FILE *f, size_t chunk_idx){
	uint32_t offset = chunk_idx * CHUNK_LEN;
	fseek(f, offset, SEEK_SET);
	return;
}

/**
 * verify whether the requested chunk has the same hash as the calculated one
 * @param f
 * @param requested_chunk_hash
 * @param chunk_idx
 */
void verify_chunk_hash(FILE *f, char *requested_chunk_hash, size_t chunk_idx){
	seek_to_chunk_pos(f, chunk_idx);
	char *buffer = Malloc(CHUNK_LEN);
	fread(buffer, 1, CHUNK_LEN, f);
	char *calculated_chunk_hash = get_chunk_hash(buffer, CHUNK_LEN);
	if (strncmp(calculated_chunk_hash, requested_chunk_hash, strlen(calculated_chunk_hash))){
		fprintf(stderr, "Unmatched chunk hashes, requested hash %, calculated"
				" hash %s\n", requested_chunk_hash, calculated_chunk_hash);
		exit(-1);
	}

	free(buffer);
	return;
}


/**
 * move the cursor the next packet to send
 * @param f
 * @param chunk_idx
 * @param last_sent_packet
 */
void seek_to_packet_pos(FILE *f, size_t chunk_idx, size_t last_sent_packet){
	size_t offset = chunk_idx * CHUNK_LEN + (UDP_MAX_PACK_SIZE -
									  PACK_HEADER_BASE_LEN) *
											 last_sent_packet;
	fseek(f, offset, SEEK_SET);
	return;
}


#ifdef _TEST_CHUNK_C_
int main(int argc, char *argv[]) {
	uint8_t *test = "dash";
	uint8_t hash[SHA1_HASH_SIZE], hash1[SHA1_HASH_SIZE];
	char ascii[SHA1_HASH_SIZE*2+1];

	shahash(test,4,hash);
	
	binary2hex(hash,SHA1_HASH_SIZE,ascii);

	printf("%s\n",ascii);

	assert(strlen(ascii) == 40);

	hex2binary(ascii, strlen(ascii), hash1);

	binary2hex(hash1,SHA1_HASH_SIZE,ascii);

	printf("%s\n",ascii);
}
#endif //_TEST_CHUNK_C_
