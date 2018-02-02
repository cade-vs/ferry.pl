
#  ferry.pl -- network file transporter
#  2010-2018 (c) Vladi Belperchinov-Shabanski "Cade" 
#  <cade@cpan.org> <cade@datamax.bg>

## INTRODUCTION

**ferry.pl** is a network file transporting utility. It scans multiple
directories and sends all found files to other machines. 

**ferry.pl** supports file integrity checks to ensure files are transported
fully and without errors (due to hardware, network or other problems).

**ferry.pl** supports SSL connections with X509 certificates to encrypt
transport connection.

## SENDING SIDE (PUSH)

Each machine, which will send files, can laucnh multiple
instances of **ferry.pl** with the following config files:

    (push.cfg)
    ---cut-----------------------------------------------------
    # PATH/MASK        DEST_IP<:PORT>:TNAME         PASSWORD

    /data-out/*.dwg    192.168.11.2:CADSYS          hereweare
    /text-out/*.txt    192.168.22.3:9911:CENTRAL2   nwrnear
    ---cut-----------------------------------------------------

Example:  ./ferry.pl push ./pull.cfg

PATH/MASK is the source files location, i.e. the files to send.

DEST_IP:PORT:TNAME is ip address, optional port and target destination name.

Target destinations (TNAME) are configured on the receiving side (pull).

:PORT is optional and defaults to 9900.

Each **ferry.pl** instance will scan all source path/masks and will send
all found files sorted by modification time, oldest first (FIFO).
If time matches, name sort will be used.

All source directories need to have existing "sent" subdirectory, where sent 
files will be moved upon correct transfer. For the example file above, they 
will be:

    /data-out/sent
    /text-out/sent


## RECEIVING SIDE (PULL)

Each machine, which will receive files, can launch multiple
instances of **ferry.pl** but on different listen ports (see help option -p)

Receiving side config files are:

    (pull.cfg)
    ---cut-----------------------------------------------------
    # TNAME             TARGET_PATH               PASSWORD

    CADSYS              /usr/local/cad/incoming   hereweare
    CENTRAL2            /home/textedit/rcv        nwrnear
    ---cut-----------------------------------------------------

Example:  ./ferry.pl pull ./pull.cfg

TNAME is a destination directory name, used by the PUSH processes.

TARGET_PATH is the actual local directory name to store received files.

## NOTES

* **ferry.pl** push/pull processes can run on the same machine as well.

* **ferry.pl** pozvolqva i SSL vryzki sys sertifikati, check "ferry.pl -h"

* All transferred files are checked for integrity using SHA1.
  SHA1 is used only for fast integrity verification.

* All passwords are checked with challenge-response scheme and WHIRLPOOL.

* By default, the delay between source files scanning is 5 seconds.
  To change it use "-l seconds" option, check "ferry.pl -h"

* File compression is possible but still not implemented (TODO).

* Sending side will skip files named "*.part" (partial), regardless MASK.

### EOF
