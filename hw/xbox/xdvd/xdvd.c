#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "qemu/osdep.h"
#include "qemu/bswap.h"
#include "ui/xemu-settings.h"
#include "WjCryptLib_Rc4.h"
#include "WjCryptLib_Sha1.h"
#include "xdvd.h"

// Ref
// https://web.archive.org/web/20240316195746/https://multimedia.cx/eggs/xbox-sphinx-protocol/
// for these constants
#define CR_TABLE_NUM_ENTRIES 773
#define CR_ENTRIES_OFFSET 774
#define CR_ENTRIES_LEN 253
#define CR_KEY_BASIS_OFFSET 1187
#define CR_KEY_BASIS_LEN 44

#ifndef ATAPI_SECTOR_SIZE
#define ATAPI_SECTOR_SIZE 2048
#endif

void xdvd_get_decrypted_responses(const uint8_t *xdvd_challenge_table_encrypted,
                                  uint8_t *xdvd_challenge_table_decrypted)
{
    Sha1Context sha_ctx;
    SHA1_HASH sha_hash;
    Rc4Context rc4_ctx;

    // Check if we have already decrypted previously
    uint32_t xdvd_magic = ldl_be_p(&xdvd_challenge_table_decrypted[4 + 12]);
    if (xdvd_magic == 0x2033AF) {
        return;
    }

    // Prepare the data for decryption
    memcpy(xdvd_challenge_table_decrypted, xdvd_challenge_table_encrypted,
           XDVD_STRUCTURE_LEN);

    // Process is basically from
    // https://web.archive.org/web/20240316195746/https://multimedia.cx/eggs/xbox-sphinx-protocol/
    // The challenge/response table is encrypted with RC4. The key is derived
    // from the CR_KEY_BASIS_OFFSET after a SHA1 hash is computed over it.
    Sha1Initialise(&sha_ctx);
    Sha1Update(&sha_ctx, &xdvd_challenge_table_encrypted[CR_KEY_BASIS_OFFSET],
               CR_KEY_BASIS_LEN);
    Sha1Finalise(&sha_ctx, &sha_hash);
    // The first 7 bytes of the SHA1 hash are fed into the RC4 initialisation
    // function as the key
    Rc4Initialise(&rc4_ctx, &sha_hash, 7, 0);
    // Then, the RC4 decrypter does its work on the CR_ENTRIES_LEN bytes of the
    // challenge/response table.
    Rc4Xor(&rc4_ctx, &xdvd_challenge_table_encrypted[CR_ENTRIES_OFFSET],
           &xdvd_challenge_table_decrypted[CR_ENTRIES_OFFSET], CR_ENTRIES_LEN);
}

// Given the already decrypted challenge table and the challenge ID sent by the
// Xbox, return the required response dword
uint32_t xdvd_get_challenge_response(const uint8_t *xdvd_challenge_table_decrypted,
                            uint8_t challenge_id)
{
    int challengeEntryCount =
        xdvd_challenge_table_decrypted[CR_TABLE_NUM_ENTRIES];
    PXBOX_DVD_CHALLENGE challenges =
        (PXBOX_DVD_CHALLENGE)(&xdvd_challenge_table_decrypted[CR_ENTRIES_OFFSET]);

    for (int i = 0; i < challengeEntryCount; i++) {
        if (challenges[i].type != 1)
            continue;

        if (challenges[i].id == challenge_id)
            return challenges[i].response;
    }

    return 0;
}

// When the Xbox DVD in not authenticated it is on the video partition (=0) and
// returns a small sector count Once the DVD is authenticated, the xbox will
// activate the game partition (=1) which retuns the full sector count
uint64_t xdvd_get_sector_cnt(XBOX_DVD_SECURITY *xdvd_security,
                             uint64_t total_sectors)
{
    if (xdvd_is_redump(total_sectors) == false) {
        return total_sectors;
    }

    // A 'redump' style iso returns XDVD_VIDEO_PARTITION_SECTOR_CNT initially
    // before it is authenticated otherwise it returns the full sector count of
    // the game data.
    if (xdvd_security->page.Authenticated == 0 ||
        xdvd_security->page.Partition == 0) {
        total_sectors = XDVD_VIDEO_PARTITION_SECTOR_CNT;
    } else {
        assert((XGD1_LSEEK_OFFSET / ATAPI_SECTOR_SIZE) < total_sectors);
        total_sectors -= (XGD1_LSEEK_OFFSET / ATAPI_SECTOR_SIZE);
    }
    return total_sectors;
}

// On the game partition, all reads to the ISO need to be offset to emulate it
// being on the game partition
uint32_t xdvd_get_lba_offset(XBOX_DVD_SECURITY *xdvd_security,
                             uint64_t total_sectors, unsigned int lba)
{
    if (xdvd_is_redump(total_sectors)) {
        if (xdvd_security->page.Authenticated == 1 &&
            xdvd_security->page.Partition == 1) {
            lba += XGD1_LSEEK_OFFSET / ATAPI_SECTOR_SIZE;
        }
    }
    return lba;
}

bool xdvd_get_encrypted_challenge_table(uint8_t *xdvd_challenge_table_encrypted)
{
    bool status = true;
    // Check if we have already read it from the file
    const char *dvd_security_path = g_config.sys.files.dvd_security_path;
    memset(xdvd_challenge_table_encrypted, 0, XDVD_STRUCTURE_LEN);

    FILE *f = qemu_fopen(dvd_security_path, "rb");
    if (f == NULL) {
        return false;
    }

    int file_size;
    fseek(f, 0, SEEK_END);
    file_size = ftell(f);
    fseek(f, 0, SEEK_SET);

    // If the security structure is read from the DVD drive it will be 1636 bytes long
    // If it is read from the DVD disk (via Kreon etc) it will be 2048 bytes long
    if (file_size == XDVD_STRUCTURE_LEN) {
        fread(xdvd_challenge_table_encrypted, 1, file_size, f);
    } else if (file_size == 2048) {
        // We have a redump style security sector. This is in a different layout to the expected
        // challenge response but we can built it up from the data we have

        // First two bytes are length of structure
        xdvd_challenge_table_encrypted[0] = (XDVD_STRUCTURE_LEN >> 8) & 0xFF;
        xdvd_challenge_table_encrypted[1] = (XDVD_STRUCTURE_LEN >> 0) & 0xFF;

        // Read header and place it in the correct place
        fread(&xdvd_challenge_table_encrypted[4], 1, 0x10, f);

        // Read challenge/response table onward to end of file
        fseek(f, CR_ENTRIES_OFFSET - 6, SEEK_SET);
        fread(&xdvd_challenge_table_encrypted[CR_ENTRIES_OFFSET - 2], 1,
              XDVD_STRUCTURE_LEN - (CR_ENTRIES_OFFSET - 2), f);
    } else {
        status = false;
    }

    fclose(f);
    return status;
}

// The Xbox will request this page before it begins sending challenges, so we
// need to be able to reply with a default structure
void xdvd_get_default_security_page(XBOX_DVD_SECURITY *xdvd_security)
{
    // Only needs a few crucial initial values to start the challenge/response
    // session
    static const XBOX_DVD_SECURITY s = {
        .header.ModeDataLength[0] = 0,
        .header.ModeDataLength[1] = sizeof(XBOX_DVD_SECURITY) - 2,
        .page.PageCode = MODE_PAGE_XBOX_SECURITY,
        .page.PageLength = sizeof(XBOX_DVD_SECURITY_PAGE) - 2,
        .page.Unk1 = 1,
        .page.BookTypeAndVersion = 0xD1,
        .page.Unk2 = 1,
    };
    memcpy(xdvd_security, &s, sizeof(XBOX_DVD_SECURITY));
};

bool xdvd_is_redump(uint64_t total_sectors)
{
    return total_sectors == XDVD_REDUMP_SECTOR_CNT;
}