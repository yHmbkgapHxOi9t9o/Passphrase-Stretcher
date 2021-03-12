package main

import (
	"fmt"
	"bufio"
	"os"
	"golang.org/x/crypto/scrypt"
	"crypto/sha256"
	"encoding/base64"
)

var info = `
This is a key stretcher. It takes a passphrase, then hashes it with both scrypt
and SHA-256, and outputs a 256 bit Base64 string.

To generate different keys for different services/platforms, take your
passphrase, and put the name of the platform on the end (all lowercase).
For example, if your passphrase is "correct horse battery staple", you could
generate a password for YouTube with "correct horse battery staple youtube".

To generate a username, do the same but with "user" on the end. For example:
"correct horse battery staple youtube user", then use the first 16 characters
of the result as your username. The first 16 characters might look like this:
"dHJ5tgYzjzdATx39".

If the service doesn't like the slashes and pluses in Base64, just remove them.
In the case of both usernames and passwords, don't bother making up for the lost
length. The loss of entropy is negligible.

If you need to provide a password (or username) that's different from previous
ones, just add a 1 at the end, and gradually increment it. Example:
"correct horse battery staple youtube 1",
"correct horse battery staple youtube 2" etc. If you forget what number you're
on, it's possible to brute force this.

Example platform names:
protonmail
backblaze bucket
rsync.net
ssh
veracrypt
borg

`

//scrypt's N value, or work factor. Must be a power of 2 (Litecoin uses 1024, so if you're assuming Litecoin ASICs are your adversary, base it on that)
var scryptn = 1048576

//number of times to repeat SHA-256
var shareps = 10000000

//if the above values are 1048576 and 10000000, then stretching takes about 10 seconds and adds ~23 bits of entropy WRT bitcoin, and ~10 bits of entropy WRT litecoin (probably more)

//scrypt salt (this is another thing to store, and it's not needed with a strong enough seed, hence the empty slice)
var scryptsalt = []byte{}

var seed string

func main() {
	fmt.Println(info)

	in := bufio.NewReader(os.Stdin)
	fmt.Print("Enter passphrase: ")
	seed, _ := in.ReadString('\n')
	seed = seed[:len(seed)-1] //removes the last /n

	scryptresult, _ := scrypt.Key([]byte(seed), scryptsalt, scryptn, 8, 1, 32)

	h := sha256.New()
	h.Write(scryptresult)
	by := h.Sum(nil)

	//SHA-256 loop
	for i := 0; i < shareps; i++ {
		h = sha256.New()
		h.Write(by)
		by = h.Sum(nil)
	}

	fmt.Println()
	//returns the base64 encoded password
	fmt.Println("Key:", base64.StdEncoding.EncodeToString(by))
	fmt.Print("Press enter to exit")
	_, _ = in.ReadString('\n')
}