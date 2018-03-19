/*
 * Copyright (c) 2018 Richard Palethorpe <rpalethorpe@suse.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef TST_CRYPTO_H
#define TST_CRYPTO_H

/* Taken from linux/crypto.h */
#define CRYPTO_MAX_ALG_NAME		64
#define CRYPTO_MAX_NAME CRYPTO_MAX_ALG_NAME

#define CRYPTO_ALG_TYPE_MASK		0x0000000f
#define CRYPTO_ALG_TYPE_CIPHER		0x00000001
#define CRYPTO_ALG_TYPE_COMPRESS	0x00000002
#define CRYPTO_ALG_TYPE_AEAD		0x00000003
#define CRYPTO_ALG_TYPE_BLKCIPHER	0x00000004
#define CRYPTO_ALG_TYPE_ABLKCIPHER	0x00000005
#define CRYPTO_ALG_TYPE_SKCIPHER	0x00000005
#define CRYPTO_ALG_TYPE_GIVCIPHER	0x00000006
#define CRYPTO_ALG_TYPE_KPP		0x00000008
#define CRYPTO_ALG_TYPE_ACOMPRESS	0x0000000a
#define CRYPTO_ALG_TYPE_SCOMPRESS	0x0000000b
#define CRYPTO_ALG_TYPE_RNG		0x0000000c
#define CRYPTO_ALG_TYPE_AKCIPHER	0x0000000d
#define CRYPTO_ALG_TYPE_DIGEST		0x0000000e
#define CRYPTO_ALG_TYPE_HASH		0x0000000e
#define CRYPTO_ALG_TYPE_SHASH		0x0000000e
#define CRYPTO_ALG_TYPE_AHASH		0x0000000f

#define CRYPTO_ALG_TYPE_HASH_MASK	0x0000000e
#define CRYPTO_ALG_TYPE_AHASH_MASK	0x0000000e
#define CRYPTO_ALG_TYPE_BLKCIPHER_MASK	0x0000000c
#define CRYPTO_ALG_TYPE_ACOMPRESS_MASK	0x0000000e

/* Taken from linux/uapi/crypto_user.h */
enum {
	CRYPTO_MSG_BASE = 0x10,
	CRYPTO_MSG_NEWALG = 0x10,
	CRYPTO_MSG_DELALG,
	CRYPTO_MSG_UPDATEALG,
	CRYPTO_MSG_GETALG,
	CRYPTO_MSG_DELRNG,
	__CRYPTO_MSG_MAX
};

struct crypto_user_alg {
	char cru_name[CRYPTO_MAX_ALG_NAME];
	char cru_driver_name[CRYPTO_MAX_ALG_NAME];
	char cru_module_name[CRYPTO_MAX_ALG_NAME];
	uint32_t cru_type;
	uint32_t cru_mask;
	uint32_t cru_refcnt;
	uint32_t cru_flags;
};

/**
 * struct tst_crypto_session
 * @fd: File descriptor for the netlink socket.
 * @seq_num: A sequence number used to identify responses from the kernel.
 *
 * Holds state relevant to a netlink crypto connection. The @seq_num is used
 * to tag each message sent to the netlink layer and is automatically
 * incremented by the tst_crypto_ functions. When the netlink layer sends a
 * response (ack) it will use the sequences number from the request.
 */
struct tst_crypto_session {
	int fd;
	uint32_t seq_num;
};

/**
 * tst_crypto_open()
 * @ses: Session structure to use, it can be uninitialized.
 *
 * Creates a crypto session. If some necessary feature is missing then it will
 * call tst_brk() with %TCONF, for any other error it will use %TBROK.
 */
void tst_crypto_open(struct tst_crypto_session *ses);

/**
 * tst_crypto_close()
 * @ses: The session to close.
 */
void tst_crypto_close(struct tst_crypto_session *ses);

/**
 * tst_crypto_add_alg()
 * @ses: An open session.
 * @alg: The crypto algorithm or module to add.
 *
 * This requests a new crypto algorithm/engine/module to be initialized by the
 * kernel. It sends the request contained in @alg and then waits for a
 * response. If sending the message or receiving the ack fails at the netlink
 * level then tst_brk() with %TBROK will be called.
 *
 * Return: On success it will return 0 otherwise it will return an inverted
 *         error code from the crypto layer.
 */
int tst_crypto_add_alg(struct tst_crypto_session *ses,
		       const struct crypto_user_alg *alg);

/**
 * tst_crypto_del_alg()
 * @ses: An open session.
 * @alg: The crypto algorithm to delete.
 * @retries: How many times the request should be repeated if %EBUSY is returned.
 *           It can be set to zero for no retries.
 *
 * Request that the kernel remove an existing crypto algorithm. This behaves
 * in a similar way to tst_crypto_add_alg() except that it is the inverse
 * operation and that it is not unusual for this to return %EBUSY. To avoid
 * needing to deal with %EBUSY you can set the retries to an appropriate value
 * like 1000.
 *
 * Return: Either 0 or an inverted error code from the crypto layer.
 */
int tst_crypto_del_alg(struct tst_crypto_session *ses,
		       const struct crypto_user_alg *alg,
		       unsigned int retries);

#endif	/* TST_CRYPTO_H */
