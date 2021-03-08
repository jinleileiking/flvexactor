#!/bin/sh 
if [ ! "$1" ];then
   echo "must input file name!"
   exit
fi

infile=$1.pcapng
outfile=$1-3
ext=flv

rm -f ${outfile}_all.${ext}

for stream in $(tshark -nlr $infile -Y tcp.flags.syn==1 -T fields -e tcp.stream | sort -n | uniq | sed 's/\r//')
do
    echo "Processing stream $stream: ${outfile}_${stream}.${ext}"
    tshark -nlr $infile -qz "follow,tcp,raw,$stream" | tail -n +7 | sed 's/^\s\+//g' | xxd -r -p | tee ${outfile}_${stream}.tmp >> ${outfile}_all.tmp
    hexdump -ve '1/1 "%.2X"' ${outfile}_${stream}.tmp |  perl -ne 'm/(464C56.*)/i && print "$1\n"' | xxd -r -p  > ${outfile}_${stream}.${ext}
done
