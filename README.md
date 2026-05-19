# LLM-Generated-Steganographic-PKC
##### Public Key Cryptographic Framework implementation based on the research paper linked below:
##### [READ PAPER HERE](https://dl.acm.org/doi/10.1145/3709018.3736332)

## Abstract
Recent advancements in Large Language Models (LLMs) have transformed communication, yet their role in secure messaging remains underexplored, especially in surveillance-heavy environments [1]. Recent work in the field of steganography has begun focusing on the inclusion of AI/ML, especially LLM’s, within novel cryptographic embedding frameworks. One such theoretical framework found in resource 1 proposes an LLM-agnostic approach for covertly embedding Public Key or Symmetric Key encrypted data within human-like texts to bypass restrictions on traditional encryption [1]. However, the practical viability of any such framework requires rigorous empirical validation. This project presents a functional proof-of-concept implementation of this novel cryptographic embedding framework. Developed in Python, our system operationalizes the theoretical model to empirically evaluate its real-world efficiency and legitimacy as a deployable product. We assess the computational overhead of the embedding process, the system’s ability to operate using independent local LLMs, and the true indistinguishability of the generated ciphertext from natural human conversation. This implementation provides critical insights into the feasibility, scalability, and operational limits of LLM-driven steganography for secure communication in restrictive digital environments.  

## Implementation

The LLM embedding framework is broken down into four different algorithms. Algorithm 1 is called “EmbedderLLM”, and outlines the core functionality of the LLM interaction and story generation. The second algorithm is called “LLM Authentication Encryption” and is responsible for generating the parameters that are fed into EmbedderLLM ultimately producing our final desired story. Algorithm 3 is called “LLM Authenticated Decryption and Verification” and outlines the decryption process of a received generated story using a shared secret password. (I recommend reading section to 3.1.2 of the attached document to understand the flow of code)


The methodology behind our project consists of explicit implementations of algorithms 1, 2, and 3 from the framework proposal paper followed by empirical testing using sampling methods, LLM selection, random payloads, and different context datasets.

## Requirements
In order to use this project to any successful capacity (for the definition of successful, please see Section 4 - CONSIDERATIONS FOR IMPROVEMENT in the document attatched to the repo), one will require a graphics card capable of running an Ollama Server and pulling a model of at LEAST 10 billion parameters. Lots of time is also required, as throughput is not fast.

## How to Use
* clone github repo
* create virtual environment
```python
python3 -m venv venv && source venv/bin/activate
```
* download all required packages
```python3
pip install -r requirements.txt
```
* run the main.py file inside virtual environment
```python3
python3 main.py
```