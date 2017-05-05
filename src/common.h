#ifndef _COMMON_H
#define _COMMON_H

#define STAGE_ERROR     -1  /* Error detected                   */
#define STAGE_INIT       0  /* Initial stage                    */
#define STAGE_HANDSHAKE  1  /* Handshake with client            */
#define STAGE_PARSE      2  /* Parse the header                 */
#define STAGE_RESOLVE    4  /* Resolve the hostname             */
#define STAGE_STREAM     5  /* Stream between client and server */

#endif