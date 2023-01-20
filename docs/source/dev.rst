.. _developer_docs:



Guide to run Puffer's Secure-Signer
========================================

Installing Rust
----------------
Puffer's Secure-Signer is programmed in Rust. To install Rust please follow these steps: 
Running the (`Warp HTTP server <https://github.com/seanmonstar/warp>`_) requires rust 1.64, to update your rust toolchain run:

.. code-block:: bash

    rustup default stable
    rustup update stable


Docker
---------

TODO 


Running the server
---------------------
In the terminal connect to the docker container:
- TODO
Start the Secure-Signer RPC on port 9000:

.. code-block:: bash

    cargo run --bin secure-signer 9000


Making Request
---------------
You can make requests in another terminal

