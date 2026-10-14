# Project 1 adversarial recipes

Replace each TODO with your selected experiment and prediction. Keep the five
section headings and the answer labels below. One short sentence or phrase
per answer is enough; put longer reasoning under **Explanation**.

**How to use the wording hints**

- The quoted hints beginning with `>` are guidance, not submitted answers.
  You may leave them in or delete them. The checker reports that quotations
  are ignored; those notices do not prevent your actual answers from parsing.
- Write your answers after the bold labels, outside the quoted hints. Replace
  the whole `TODO`; do not put your answer in a code block or add a new heading.
  Keep the blank line between each hint block and the first answer so Markdown
  does not treat that answer as part of the quotation.
- The examples illustrate wording the parser understands, including weaker
  or incorrect predictions. Choose what you intend to test and predict;
  do not paste every alternative into the answer.
- In a sentence pattern such as `raises <exception>`, replace the placeholder
  with one exception name from that experiment's catalogue. A bare `reject`
  or a list such as `InvalidTag or ProtocolError` needs staff review.
- Common shorthand works: `msg`/`msgs` = message(s), `ct` = ciphertext,
  `recv`/`rcv`/`rx` = receiving, `ctr` = counter, `hs` = handshake,
  `eph` = ephemeral, `orig` = original, `prev` = previous, `sess` = session,
  `auth` = authentication, `proto` = protocol, `err` = error,
  `w/` = with, and `w/o` = without. Case and ordinary punctuation are flexible.
- **Explanation** is optional. Replace its TODO with your reasoning, leave it
  blank, or remove that field. Explanations are not interpreted as answer choices.

Run `python3 validate_adversarial_recipes.py --choices` to see the available
interpretations and more wording examples. After editing, run
`python3 validate_adversarial_recipes.py adversarial_recipes.md`.
Check the interpreted choices for all five sections, not just whether the
command succeeds. A preview confirms what was read, not whether it earns marks.
If a phrase needs review, try a shorter sentence from the catalogue and move
the surrounding reasoning into **Explanation**. You can ask staff if the
available wording does not express your intended experiment.

## Identity and transcript substitution

> **Wording help**
> - **Attack:** choose one handshake substitution. The catalogue includes a
>   self-signed identity using the same name, replacing the signed ephemeral
>   key, and changing a signed nonce bit. Phrases such as `replace the signed
>   eph key` and `flip a bit in the signed nonce` are understood.
> - **Expected result:** use `raises <exception>` or `no exception`, choosing
>   the prediction you think follows from the handshake checks.
> - **State after rejection:** distinguish the active session from the pending
>   handshake. For example, `active and pending state unchanged`,
>   `only active sess stays same`, and `pending hs is consumed` mean different things.
> - **Control:** specify which handshake or session you exercise afterward.
>   `retry the orig hs, then exchange msgs` and `exchange msgs only in the old
>   sess` describe different controls; choose the one your argument needs.
> - **Explanation:** explain which identity or signed-transcript check your
>   substitution tests and what the control would demonstrate.

**Attack:** Use a self-signed identity with the same name

**Expected result:** Raises AuthenticationError

**State after rejection:** Active and pending state unchanged

**Control:** Retry the orig hs, then exchange msgs

**Explanation:** The attack fails because of the identity check. The control demonstrates that Alice only rejected Mallory's handshake since the pending handshake is still intact.

## AAD binding

> **Wording help**
> - **Attack:** change only the associated data. Supported descriptions include
>   `flip the first AAD bit`, `append a byte to the AAD`, and `replace all AAD bytes`.
>   The key, nonce, and ciphertext are held fixed in this experiment.
> - **Expected result:** use `raises <exception>` or `no exception`. Choose the
>   exception from the catalogue that matches your prediction.
> - **Control:** name both the ciphertext and the AAD used in the legitimate
>   decryption. The pattern `decrypt the <original or fresh> ct w/ the correct
>   AAD` is understood after you choose one word and remove the placeholder.
>   Original and fresh ciphertexts are different controls.
> - **Explanation:** explain what your comparison would show about AAD binding.

**Attack:** Flip the first bit of the AAD, keeping the key, nonce, and ciphertext unchanged.

**Expected result:** Raises InvalidTag.

**Control:** Decrypt the original ciphertext with the correct AAD.

**Explanation:** Only the AAD changes, so rejection checks whether the ciphertext is authenticated together with its associated data. Decrypting the same ciphertext with the original AAD checks that legitimate decryption still works.

## Ciphertext rejection without committing state

> **Wording help**
> - **Attack:** choose `flip the first bit of ct` or `flip the last bit of ct`.
>   This experiment changes the ciphertext of a valid out-of-order message.
> - **Expected result:** use `raises <exception>` or `no exception` for your prediction.
> - **State after rejection:** describe the scope of your prediction.
>   `recv state doesn't change`, `only recv ctr unchanged`, and `receiving
>   state advances` have different meanings. Full receiving state includes
>   the chain key, counter, and skipped-message keys.
> - **Control:** distinguish retrying the same original message from trying
>   another message. For example, `retry the orig msg` and `send fresh msg only`
>   are both understood, but they test different properties.
> - **Explanation:** connect the state prediction and control to what happens
>   after a failed decryption.

**Attack:** Flip the first bit of ct

**Expected result:** InvalidTag

**State after rejection:** Recv state doesn't change

**Control:** Retry the orig msg

**Explanation:** After a failed decryption, the receiving state does not commit, therefore its state remains the same.  

## Replay after reordering

> **Wording help**
> - **Delivery order:** choose `2, 0, 1`, `2, 1, 0`, or `1, 0, 2`.
>   You can also write arrows or words, such as `msgs 2 then 0 then 1`.
>   These are message numbers, starting at zero, not counts of delivered messages.
> - **Replay message:** name one target, `msg 0` or `msg 1`.
>   For the skipped-key replay experiment, the target must be smaller than
>   the first number in your delivery order. Do not paste both choices.
> - **Expected result:** predict the outcome of the replay, using
>   `raises <exception>` or `no exception`.
> - **State after rejection:** use the same receiving-state wording as above;
>   specify full state or just the counter according to your prediction.
> - **Control:** say whether you check each original delivery as well as later
>   traffic. The catalogue distinguishes `accept each msg once, then exchange
>   msgs in the same sess` from `only exchange msgs in the same sess`.
> - **Explanation:** explain how the chosen order exercises skipped keys and
>   why the later delivery is a replay.

**Delivery order:** 2, 0, 1

**Replay message:** 1

**Expected result:** ReplayError

**State after rejection:** Recv state doesn't change

**Control:** Accept each msg once, then exchange msgs in the same sess

**Explanation:** The chosen order skips keys since message 2 arrives first, therefore the receiver ratches through positions 0 and 1, saving their keys as skipped keys, and setting receive_count to 3.  When the adversary replays message 1, since 1 < receive_count, and no key is retained for it, a ReplayError is thrown.

## Old-session rejection

> **Wording help**
> - **Attack:** identify the session and whether the message was previously
>   delivered. Use a pattern such as `deliver an <undelivered or already
>   delivered> msg from the prev sess`, choosing one description and removing
>   the placeholder. `deliver a msg from the fresh sess` is a different choice.
> - **Expected result:** use `raises <exception>` or `no exception` to predict
>   what happens when this message reaches the receiver after a fresh session
>   has been established.
> - **State after rejection:** describe the receiver's state in the fresh
>   session. `recv state stays the same` and `recv state advances` are distinct
>   predictions; counter-only wording has a narrower meaning.
> - **Control:** name the session used for legitimate traffic. For example,
>   `exchange msgs in the fresh sess` and `exchange msgs only in the old sess`
>   specify different controls.
> - **Explanation:** explain how your chosen message distinguishes session
>   separation from rejecting a message that has already been consumed.

**Attack:** Undelivered msg from the prev sess

**Expected result:** ProtocolError

**State after rejection:** Recv state stays the same

**Control:** Exchange msgs in the fresh sess

**Explanation:** The old message's session_id does not match the session_id from the fresh session