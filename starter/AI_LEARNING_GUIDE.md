# Project 1: Learning with AI

You may use AI to write and debug your project code and to draft or revise
`adversarial_recipes.md`. This optional guide suggests ways to learn from that
help: think through a small example, build something that works, then ask
questions about why it works.

The [README](README.md) explains the project and its security assumptions.
The README and starter-code docstrings specify what your implementation must
do. Give the AI the relevant section and code so it can work from those
requirements. You do not need to restate the threat model or prepare diagrams
before asking for help.

There are no marks or required submissions for this guide, and you do not
submit chat logs. Use whichever prompts help you; there is no required number
of questions. AI is optional, no paid tool is needed, and you can explore the
same questions with your project partner or a TA. Follow the course's
collaboration and AI-disclosure rules.

## How to use the prompts

Each milestone has two parts:

1. **Think it through, then build.** Ask AI to explain one small example and
   help you think about the key decision. Then ask it to write, complete, or
   improve the code. You can ask for an explanation whenever you get stuck;
   you do not need a finished answer or your own implementation first.
2. **Ask about what you built.** Choose a follow-up question about the code or
   result. Try a quick prediction if you can, then ask AI to explain and help
   you check it with a small example or test. The aim is to connect the answer
   to your actual program.

The quoted text below can be copied into a chat. For Part 2, choose one
question at a time rather than asking all of them at once. Share the current
code, test output, or recipe when the question refers to it.

If helpful, start the conversation with:

> Help me learn while completing CSC364 Project 1. Use the README and starter
> docstrings as the requirements. Explain unfamiliar terms in plain language
> and use small text examples. Ask one focused question at a time when that
> helps me think, and explain if I do not know the answer. You may write code
> and draft the adversarial-recipe Markdown for me. Explain the important
> choices in what you produce and help me test them. If information is missing,
> ask for the relevant file or excerpt instead of inventing a requirement.

## 1. Agree on a secret: ECDH

### Part 1: Think it through, then build

> Help me understand how Alice and Bob use ECDH to agree on a secret. Start
> with which values Alice keeps private and which she can send to Bob, then
> explain Bob's side. Use a short text example and invite me to predict which
> keys each person combines. Then help me implement the ECDH TODOs in the
> starter, following its key-type and P-384 curve checks. Help me test that
> both sides get the same shared bytes and that unsupported keys are rejected.

### Part 2: Ask about what you built

> In our code, where does Alice use her private key and Bob's public key?
> Walk me through why Bob can obtain the same shared bytes.

> If both participants get the same secret, why does that not yet prove
> that Alice is talking to Bob? Explain what the later handshake adds.

> Show me one local test using a key on the wrong curve. Which function
> should reject it, and where does the starter specify the exception?

## 2. Derive and update keys: KDF and ratchet

### Part 1: Think it through, then build

> Help me understand the two outputs of `ratchet_key`: the key for one message
> and the chain key saved for later. Use names such as "current chain key"
> and "message 0 key", not actual secret bytes. Ask me which value we should
> keep after sending. Then help me implement `hkdf_expand` and `ratchet_key`
> with the exact labels and parameters from the README. Help me test that
> the same inputs reproduce the same outputs and that the two outputs differ.

### Part 2: Ask about what you built

> Why do we use different HKDF labels for the next chain key and the message
> key? Show me where our code makes that distinction.

> What would go wrong if we used the next chain key itself to encrypt a
> message? Explain the different jobs of these two keys.

> Suppose someone steals the current chain key. Which earlier and later
> message keys could they obtain? Explain separately what changes if they
> also steal keys we have saved for delayed messages.

## 3. Protect one message: encryption and input checks

### Part 1: Think it through, then build

> Help me understand what AES-GCM encrypts and what it checks without hiding.
> Use a message and its visible header as the example. Ask me to predict
> what should happen if the header changes. Then help me implement the
> encryption, decoding, and decryption TODOs. Follow the starter's input
> checks and exception rules. Help me test normal decryption, a malformed
> encoding, and a well-formed encrypted message that has been tampered with.

### Part 2: Ask about what you built

> How can the header stay readable while changes to it are detected? Point
> to where our code passes it as additional authenticated data, or AAD.

> Why is malformed hexadecimal input different from a correctly encoded
> ciphertext whose authentication check fails? Show the two paths in our code.

> Help me test `decrypt_message` by changing only the AAD while keeping the
> key, nonce, and ciphertext fixed. Why should we also try the original AAD,
> and what would changing both the AAD and ciphertext fail to tell us?

## 4. Create a handshake

### Part 1: Think it through, then build

> Walk me through one handshake payload using the README's fields. Start
> with why it contains both an identity key and a temporary ECDH public key.
> Help me think about which values should be new for each session. Then
> help me implement handshake creation and the relevant parsing TODOs.
> Follow the exact JSON encoding, signature, freshness, and pending-handshake
> rules. Help me check that a generated handshake's signature verifies.

### Part 2: Ask about what you built

> Which exact bytes does our code sign? How are those different from the
> complete message we send after adding the signature?

> Show me two JSON encodings with the same fields but different spacing or
> field order. Why does this project accept only one encoding? Connect the
> rule to the sender and receiver code.

> Which values stay the same across sessions, and which must be generated
> again? Show me where our code handles each one.

## 5. Establish a session

### Part 1: Think it through, then build

> Help me follow a received handshake through `establish_session`. Start
> with one question: should we trust an identity key just because it arrived
> in the message? Use the README's trusted-key setup to explain the checks.
> Then help me implement session establishment, including the common
> handshake ordering and the two message directions. Help me test that
> Alice's sending key matches Bob's receiving key and vice versa, and that
> a failed attempt leaves the previous active and pending state unchanged.

### Part 2: Ask about what you built

> If an attacker signs a handshake with their own key but uses Bob's name,
> which check in our code should catch it? Why is checking the signature
> against the key inside the message not enough?

> What happens if each person combines their own handshake first and the
> other person's second? Show why the initiator/responder ordering matters.

> If a new session fails to establish, can we still use the old session and
> retry the pending handshake? Walk me through which assignments must wait
> until all checks have passed.

## 6. Send and receive messages in order

### Part 1: Think it through, then build

> Help me follow one message from `send` to `receive`. Start by explaining
> which key protects it and how its message number is chosen. Ask me what
> should happen to the receiver's stored values if decryption fails. Then
> help me implement the in-order path, following the README's header,
> counter, and state-update rules. Help me test normal messages, a tampered
> message, and successful delivery of the original after that rejection.

### Part 2: Ask about what you built

> Where does our code calculate possible new keys and counters, and where
> does it actually save them? Why are those separate steps?

> What would happen if we advanced the receiving key before checking the
> message? Help me try a small example and compare it with the correct code.

> Why should a message from an earlier session be rejected even if its
> message number looks right? Show me which header check handles this.

## 7. Handle delayed messages and replays

### Part 1: Think it through, then build

> Alice sends messages 0, 1, and 2, but Bob receives message 2 first. Help me
> think about what Bob needs to save so he can still read messages 0 and 1
> later. Explain one delivery at a time; I do not need to prepare a state
> table. Then help me implement skipped-message keys, replay rejection, and
> the total `MAX_SKIP` limit. Help me test delivery order 2, 0, 1, followed
> by a replay, and check that valid later traffic still works.

### Part 2: Ask about what you built

> After Bob accepts message 2 first, why is `receive_count` not the number
> of messages he has read? Walk through the counter and saved keys with me.

> What if we change only the ciphertext of delayed message 0, keeping its
> encoding and length valid, and deliver that copy before the original?
> Which stored values must stay unchanged so the original can still work?
> Help me test this without printing secret key bytes.

> Why does `MAX_SKIP` count all saved skipped keys, including keys from
> earlier gaps? Help me construct a small example showing why checking
> only the newest gap is not enough.

## 8. Write and understand the adversarial recipes

### Part 1: Think it through, then draft

> Help me work through the five experiments in `adversarial_recipes.md`,
> one section at a time. Use the README, supplied template, and public
> checker's choices. Start by explaining what the current experiment is
> trying to check, and invite me to predict the result of one allowed change.
> Then draft the Markdown answers with me, including the exact expected
> exception, state behavior where requested, and the legitimate operation
> that should still succeed. You may write the answers; explain why each
> one fits the experiment. Keep the required headings and answer format.

Use the public checker on the draft:

```bash
python3 validate_adversarial_recipes.py --choices
python3 validate_adversarial_recipes.py adversarial_recipes.md
```

Share the output with AI if you want help interpreting it or revising wording.
The checker shows how it reads your answers; it does not tell you whether the
experiments are correct. Compare its interpretation with what you intend.

### Part 2: Ask about what you drafted

> Explain this recipe in plain language: what does the attacker change,
> what should be rejected, and what normal operation should still work?
> Point to the corresponding fields in our draft.

> Why do the AAD and ciphertext experiments change different inputs?
> What could we mistakenly conclude if we changed both at once?

> Our recipe predicts an exception. Why is that alone not enough? Help me
> understand what the unchanged-state check and legitimate control each show.

> The checker understood our report. Could the experiment still be wrong?
> Help me compare one prediction with the README and check that our wording
> describes the intended experiment.

## When an explanation still does not make sense

You can ask for a different explanation without preparing another exercise:

> Explain that with one message and point to the relevant lines in my code.

> Which part is required by this project's specification, and which part
> is just one way to write the Python code?

> Give me a small "what if we changed this?" example. Let me make a prediction,
> then explain the result and help me test it.

If you prefer to be quizzed, you can also ask:

> Ask me one short question about the code or recipe we just produced. Wait
> for my answer, then explain anything I missed using the README.

Before moving on, see whether you can explain one important choice in your own
words. If not, ask another question or try another example. AI explanations
and passing tests are useful checks, but neither is a proof of security.
