#ifndef HW_XDVD_XBOX_H
#define HW_XDVD_XBOX_H

#include <stdint.h>

// Ref https://web.archive.org/web/20230331163919/https://multimedia.cx/eggs/xbox-sphinx-protocol/
// Ref https://xboxdevwiki.net/Xbox_Game_Disc
// Ref https://xboxdevwiki.net/DVD_Drive

// This is the start of the Xbox game data
#define XGD1_LSEEK_OFFSET 0x18300000UL 

// The sector count of the video parition of a Xbox DVD
#define XDVD_VIDEO_PARTITION_SECTOR_CNT 6992 

// The sector count of 'redump' iso files
#define XDVD_REDUMP_SECTOR_CNT 3820880

// Page Code for Xbox Security Challenges (over SCSI)
#define MODE_PAGE_XBOX_SECURITY 0x3E 

#define XDVD_STRUCTURE_LEN 0x664
#define DVD_SECURITY_PAGE_LEN 28


typedef struct _MODE_PARAMETER_HEADER10 {
    uint8_t ModeDataLength[2];
    uint8_t MediumType;
    uint8_t DeviceSpecificParameter;
    uint8_t Reserved[2];
    uint8_t BlockDescriptorLength[2];
} __attribute__((packed)) MODE_PARAMETER_HEADER10, *PMODE_PARAMETER_HEADER10;
_Static_assert(sizeof(MODE_PARAMETER_HEADER10) == 8,
               "sizeof(MODE_PARAMETER_HEADER10) != 8");

// https://xboxdevwiki.net/DVD_Drive
typedef struct _XBOX_DVD_SECURITY_PAGE {
    uint8_t PageCode;
    uint8_t PageLength;
    uint8_t Partition; // 0 - video, 1 - xbox
    uint8_t Unk1;
    uint8_t Authenticated;
    uint8_t BookTypeAndVersion;
    uint8_t Unk2;
    uint8_t ChallengeID;
    uint32_t ChallengeValue;
    uint32_t ResponseValue;
    uint32_t Unk3;
} __attribute__((packed)) XBOX_DVD_SECURITY_PAGE, *PXBOX_DVD_SECURITY_PAGE;
_Static_assert(sizeof(XBOX_DVD_SECURITY_PAGE) == 20,
               "sizeof(XBOX_DVD_SECURITY_PAGE) != 20");

// DVD Mode Select/Mode Sense Security struct
typedef struct _XBOX_DVD_SECURITY {
    MODE_PARAMETER_HEADER10 header;
    XBOX_DVD_SECURITY_PAGE page;
} __attribute__((packed)) XBOX_DVD_SECURITY;
_Static_assert(sizeof(XBOX_DVD_SECURITY) == 28,
               "sizeof(XBOX_DVD_SECURITY) != 28");

typedef struct _XBOX_DVD_CHALLENGE {
    uint8_t type;
    uint8_t id;
    uint32_t challenge;
    uint8_t reserved;
    uint32_t response;
} __attribute__((packed)) XBOX_DVD_CHALLENGE, *PXBOX_DVD_CHALLENGE;
_Static_assert(sizeof(XBOX_DVD_CHALLENGE) == 11);

uint32_t xdvd_get_challenge_response(const uint8_t *xdvd_challenge_table_decrypted,
                                     uint8_t challenge_id);
 
void xdvd_get_default_security_page(XBOX_DVD_SECURITY *xdvd_security);

uint64_t xdvd_get_sector_cnt(XBOX_DVD_SECURITY *xdvd_security, uint64_t total_sectors);
 
uint32_t xdvd_get_lba_offset(XBOX_DVD_SECURITY *xdvd_security, unsigned int lba);

void xdvd_get_encrypted_challenge_table(uint8_t *xdvd_challenge_table_encrypted);

void xdvd_get_decrypted_responses(const uint8_t *xdvd_challenge_table_encrypted, uint8_t *xdvd_challenge_table_decrypted);

bool xdvd_is_redump(uint64_t total_sectors);
#endif