#!/bin/bash

openssl dgst -sha1 -sign private_key my_message.txt > my_message.sig
openssl dgst -sha1 -verify vk.pem -signature my_message.sig my_message.txt
