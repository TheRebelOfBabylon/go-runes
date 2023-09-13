# go-runes
Runes for authentication (like macaroons only simpler) ported to Go. The original Python implementation is found [here](https://github.com/rustyrussell/runes)

I'm by no means an expert in cryptography so please, if you see something bad, PRs are welcome.

## What are Runes?

Runes are like cookies for authorization but extra restrictions can be added by clients and shared with others. Those runes can then still be authenticated by the server.

## Rune Language

A *rune* is a series of restrictions; you have to pass all of them (so
appending a new one always makes the rune less powerful).  Each
restriction is one or more alternatives ("cmd=foo OR cmd=bar"), any
one of which can pass.

The form of each alternative is a simple string:

    ALTERNATIVE := FIELDNAME CONDITION VALUE

`FIELDNAME` contains only UTF-8 characters, exclusive of
! " # $ % & ' ( ) * +, - . / : ;  ? @ [ \ ] ^ _ \` { | } ~ (C's ispunct()).
These can appear inside a `VALUE`, but `&`, `|` and `\\` must be escaped with `\` (escaping is legal for any character, but unnecessary).


`CONDITION` is one of the following values:
* `!`: Pass if field is missing (value ignored)
* `=`: Pass if exists and exactly equals
* `/`: Pass if exists and is not exactly equal
* `^`: Pass if exists and begins with
* `$`: Pass if exists and ends with
* `~`: Pass if exists and contains
* `<`: Pass if exists, is a valid integer (may be signed), and numerically less than
* `>`: Pass if exists, is a valid integer (may be signed), and numerically greater than
* `}`: Pass if exists and lexicograpically greater than (or longer)
* `{`: Pass if exists and lexicograpically less than (or shorter)
* `#`: Always pass: no condition, this is a comment.

Grouping using `(` and `)` may be added in future.

A restriction is a group of alternatives separated by `|`; restrictions
are separated by `&`.
e.g.

    cmd=foo | cmd=bar
	& subcmd! | subcmd{get

The first requires `cmd` be present, and to be `foo` or `bar`.  The second
requires that `subcmd` is not present, or is lexicographically less than `get`.
Both must be true for authorization to succeed.


## Rune Authorization

A run also comes with a SHA-256 authentication code.  This is
generated as SHA-256 of the following bytestream:

1. The secret (less than 56 bytes, known only to the server which issued it).
2. For every restriction:
   1. Pad the stream as per SHA-256 (i.e. append 0x80, then zeroes, then
      the big-endian 64-bit bitcount so far, such that it's a multiple of 64
      bytes).
   2. Append the restriction.

By using the same padding scheme as SHA-256 usually uses to end the
data, we have the property that we can initialize the SHA-256 function
with the result from any prior restriction, and continue.

The server can validate the rune authorization by repeating this
procedure and checking the result.


## Rune Encoding

Runes are encoded as base64, starting with the 256-bit SHA256
authentication code, the followed by one or more restrictions
separated by `&`.

Not because base64 is good, but because it's familiar to Web people;
we use RFC3548 with `+` and `/` replaced by `-` and `_` to make
it URL safe.

(There's also a string encoding which is easier to read and debug).

## Best Practices

It's usually worth including an id in each rune you hand out so that
you can blacklist particular runes in future (your other option is to
change your master secret, but that revokes all runes).  Because this
appears in all runes, using the empty fieldname (''), and a simple
counter reduces overall size, but you could use a UUID.

This is made trivial by the `unique_id` parameter to Rune() and
MasterRune(): it adds such an empty field with the unique id (which
the default evaluator will ignore unless you handle it explicitly).

You may also include version number, to allow future runes to have
different interpretations: this appends '-[version]' in the '' field:
the default handler will fail any cookie that has a version field
(for safe forward compatibility).

The rune unmarshalling code ensures that if an empty parameter exists,
it's the first one, and it's of a valid form.


## API Example

make a rune

```go
package main

import (
    "log"

    "github.com/TheRebelOfBabylon/go-runes"
)

func main() {
    secret := make([]byte, 16)

    // make a top level rune with no id
    masterRune, err := runes.NewMasterRune(secret, "", "")
    if err != nil {
        log.Fatal(err)
    }
    log.Printf("masterrune=%s", masterRune.encode())
}
```

add a restriction

```go
package main

import (
    "log"

    "github.com/TheRebelOfBabylon/go-runes"
)

func main() {
    ...
    restr, err := runes.RestrictionFromString("f1=1")
    if err != nil {
        log.Fatal(err)
    }
    if err = masterRune.AddRestriction(restr); err != nil {
        log.Fatal(err)
    }
}
```

parse a rune and test its authenticity

```go
package main

import (
    "log"

    "github.com/TheRebelOfBabylon/go-runes"
)

func main() {
    ...
    newRune, err := runes.RuneFromEncodedString(masterRune.encode())
    if err != nil {
        log.Println(err)
    }
    // check if it's legit
    if err = masterRune.Check(newRune.encode(), map[string]runes.Test{"f1": {"1", runes.StandardTestFunc}}); err != nil {
        log.Println(err)
    }
}
```

make a custom test function for your runes

```go
package main

import (
    "log"

    "github.com/TheRebelOfBabylon/go-runes"
)

func main() {
    ...
    var customTestFunc runes.TestFunc = func(alt *runes.Alternative, v interface{}) error {
        // do some interesting, custom authentication. Maybe rate limiting
        return nil
    }
    // check if it passes our custom test func
    if err = masterRune.Check(newRune.encode(), map[string]runes.Test{"f1": {"1", customTestFunc}}); err != nil {
        log.Println(err)
    }
}
```


## Author
The original author of the idea and the creator of the [original implementation](https://github.com/rustyrussell/runes) is Rusty Russell.
