.. secure-signer documentation master file, created by
   sphinx-quickstart on Wed Jan 11 13:35:57 2023.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

.. image:: ../images/Horizontal@2x.png
	:width: 300px

Introduction
============
Welcome to Puffer's Secure-Signer documentation!
------------------------------------------------
Secure-Signer is a remote signing tool that implements the same specs as (`Web3Signer <https://consensys.github.io/web3signer/web3signer-eth2.html>`_), 
making it compatible with existing consensus clients. Secure-Signer is designed to run on 
Intel SGX via the Occlum LibOS to protect Ethereum validators from (`slashable offenses <https://github.com/ethereum/consensus-specs/blob/master/specs/phase0/validator.md#how-to-avoid-slashing>`_).
Validator keys are safeguarded in SGX's encrypted memory and the hardware enforces that Secure-Signer can only sign non-slashable messages. 
This reduces validator risk from slashing either from accidents or if their system is compromised.



.. toctree::
   :maxdepth: 2
   :hidden:
   :caption: Getting Started:

   self
   dev.rst

.. * :ref:`genindex`
.. * :ref:`modindex`
.. * :ref:`search`
