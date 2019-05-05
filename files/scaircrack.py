#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Derive WPA keys from Passphrase and 4-way handshake info

Calcule un MIC d'authentification (le MIC pour la transmission de données
utilise l'algorithme Michael. Dans ce cas-ci, l'authentification, on utilise
sha-1 pour WPA2 ou MD5 pour WPA)
"""

__author__      = "Abraham Rubinstein"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "abraham.rubinstein@heig-vd.ch"
__status__ 		= "Prototype"

from scapy.all import *
from binascii import a2b_hex, b2a_hex
from pbkdf2_math import pbkdf2_hex
from numpy import array_split
from numpy import array
import hmac, hashlib


# MODIFICATION SCAIRCRAK: ouverture du dicionnaire et récupération de chaque ligne
wordsFile = open("wordlist")
dico = wordsFile.read().splitlines()
wordsFile.close()


arp = rdpcap('wpa_handshake.cap')

def customPRF512(key,A,B):
    """
    This function calculates the key expansion from the 256 bit PMK to the 512 bit PTK
    """
    blen = 64
    i    = 0
    R    = ''
    while i<=((blen*8+159)/160):
        hmacsha1 = hmac.new(key,A+chr(0x00)+B+chr(i),hashlib.sha1)
        i+=1
        R = R+hmacsha1.digest()
    return R[:blen]

# Read capture file -- it contains beacon, authentication, associacion, handshake and data
wpa=rdpcap("wpa_handshake.cap") 

# Important parameters for key derivation - most of them can be obtained from the pcap file
A           = "Pairwise key expansion" #this string is used in the pseudo-random function
ssid        = arp[3].info
APmac       = a2b_hex(arp[5].addr2.replace(':', ''))
Clientmac   = a2b_hex(arp[5].addr1.replace(':', ''))


# Authenticator and Supplicant Nonces
ANonce      = arp[5].load[13:45]
SNonce	    = arp[6].load[13:45]

# This is the MIC contained in the 4th frame of the 4-way handshake
# When attacking WPA, we would compare it to our own MIC calculated using passphrases from a dictionary
mic_to_test = b2a_hex(arp[8].load)[154:186]

B           = min(APmac,Clientmac)+max(APmac,Clientmac)+min(ANonce,SNonce)+max(ANonce,SNonce) #used in pseudo-random function

data        = a2b_hex("0103005f02030a0000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000") #cf "Quelques détails importants" dans la donnée

foundPP = False;

# MODIFICATION SCAIRCRACK: parcours des mots du dico
for passPhrase in dico:
    print("Testing with passphrase: " + passPhrase)
    #calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
    pmk = pbkdf2_hex(passPhrase, ssid, 4096, 32)

    #expand pmk to obtain PTK
    ptk = customPRF512(a2b_hex(pmk),A,B)

    #calculate MIC over EAPOL payload (Michael)- The ptk is, in fact, KCK|KEK|TK|MICK
    mic = hmac.new(ptk[0:16],data,hashlib.sha1)
    print("mic: " + str(mic.hexdigest()[:len(mic_to_test)]))
    print("mic to test: " + mic_to_test + '\n')

    # MODIFICATION SCAIRCRACK: comparaison mic généré et mic attendu
    if mic.hexdigest()[:len(mic_to_test)] == mic_to_test:
        print("\nFound passphrase! It's: " + passPhrase + "\n")
        
        
        print "\nResults of the key expansion"
        print "============================="
        print "PMK:\t\t",pmk,"\n"
        print "PTK:\t\t",b2a_hex(ptk),"\n"
        print "KCK:\t\t",b2a_hex(ptk[0:16]),"\n"
        print "KEK:\t\t",b2a_hex(ptk[16:32]),"\n"
        print "TK:\t\t",b2a_hex(ptk[32:48]),"\n"
        print "MICK:\t\t",b2a_hex(ptk[48:64]),"\n"
        print "MIC:\t\t",mic.hexdigest(),"\n"
        foundPP = True
        break

if not foundPP:
	print("Sorry, none of these passphrases worked!")
