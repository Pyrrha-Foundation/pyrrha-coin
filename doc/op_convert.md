<div class="cwikmeta">
{
"title": "OP_CONVERT"
} </div>

# OP_CONVERT
*Convert next N items on stack onto push-only minimally encoded data chunk, or split a data chunk into its constituents and a remainder*

## Rationale

This opcode cand be used (among other usecases) to parse locking bytecode into its components (groupId, groupAmount, templateHash, constraintHash, [visibleArgs...]) and to assemble stack primitives into minimally encoded data chunks concatenated into single data blob.

This compact data representation can be unpacked into data structures (`02feed02f00d` for `[0xfeed, 0xf00d]`), or even nested data structures (`0602feed02f00d0602dead02beef`" for `[[0xfeed, 0xfood], [0xdead, 0xbeef]]`) of arbitrary depth of nesting.

## Syntax and Stack

N > 0: *data chunk N* ... *data chunk 1* *count* **OP_CONVERT** => push_only_data_blob<sup>*[?](/blockchain/script.md)*</sup>

N < 0: *push_only_data_blob* *count* **OP_CONVERT** => data chunk N (N > count), ..., data chunk 1, unparsed remainder

N == 0: *push_only_data_blob* *OP_0* **OP_CONVERT** => data chunk N, ..., data chunk 1, parsed chunks count

- *data chunk*: Any VM stack element which can be minimally encoded
- *push_only_data_blob*: a stack element which encodes data chunk elements, minimally encoded. See examples
- *count* script number (not a BigNum), postive, negative or zero, which steers the execution of the opcode.

### Binary representation
OP_CONVERT is represented by the single byte 0xe8.

## Operation

### Data Specifiers

*count* must be a CScriptNum. *count* is popped from the stack.

This opcode is a codec, meaning that it can do both, encode and decode data. The behaviour is steered by its first argument *count*.

If count is negative, the stack item next to *count* will be considered as push-only data blob and split into *count* constituents of data. If *count* is less than number of data pushes in the blob, the unparsed remainder will be located on the top of the stack for further pushes or for it to be discarded from further processing. If requested *count* is greater than the amount of pushes in the data blob, the script execution will fail.

If *count* is exactly 0, the behaviour is the same as described above, but the entire data blob will be consumed for parsing. The amount of parsed data chunks will be pushed to the top as the result of the opcode execution.

If *count* is positive, the next *count* items on stack will be popped and consumed by the opcode, minimally encoded and concatenated in the order of appearance into a data blob which will be pushed to the stack. If *count* is greater than the size of the stack, the script execution will fail.

## Examples

Assuming the opcodes read and executed by VM left to right and stack elements located left to right (appearance) from top of the stack to the bottom of the stack:

* `OP_CONVERT -> fail` // no count argument
* `OP_1 OP_CONVERT -> fail` // no data
* `<02f00d> OP_2 OP_CONVERT -> fail` // 2 chunks expected, 1 chunk provided
* `OP_1 OP_2 OP_CONVERT -> fail` // 2 items expected to be encoded, 1 item on stack provided
* `<02f00d02beef02feed> OP_0 OP_CONVERT -> OP_3 <feed> <beef> <f00d>` // parsed all, pared item count on top of the stack
* `<02f00d02beef02feed> OP_3 OP_NEGATE OP_CONVERT -> <feed> <beef> <f00d>` // parsed all requested items
* `<02f00d02beef02feed> OP_1NEGATE OP_CONVERT -> <02beef02feed> <f00d>` // parse 1 item from data, unparsed remainder is left on top of the stack
* `OP_1 OP_0 OP_1NEGATE <"AB"> OP_4 OP_CONVERT -> <0241424f0051>` // encode various data primitives into minimally encoded data blob
* `OP_1 OP_0 <"AB"> OP_2 OP_CONVERT -> <02414200> OP_1` // 2 items out of 3 are encoded, 1 is left on stack
* `OP_1 OP_0 <"AB"> OP_1 OP_CONVERT -> <024142> OP_0 OP_1` // 1 item out of 3 is encoded, 2 are left on stack
* `<02f00d02beef02feed> OP_0 OP_CONVERT OP_CONVERT -> <02feed02beef02f00d>` // inversion of OP_CONVERT results in the inverted data blob compared to initial data blob