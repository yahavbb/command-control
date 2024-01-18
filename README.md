# Command & Control (C&C) Application

This project implements a Command & Control (C&C) system in Python, which is typically used to issue commands and control remote systems (agents) in a network. The `server.py` serves as the C&C server, which issues commands and controls the connected agents. The `agent.py` acts as the client that executes commands received from the C&C server.

## Description

The `server.py` script is the central component of the C&C system. It listens for connections from agents and can issue commands to all connected agents.

The `agent.py` script runs on the client machine. It connects to the C&C server and awaits commands, which it then executes locally.

## Getting Started

### Installing
Ensure Python 3.x and scapy are installed on both the server and agent systems.

### Running the Application

To start the C&C server, run:

```bash
python server.py
```

On the agent machine(s), run the agent script:

```bash
python agent.py
```

Make sure that the `agent.py` is configured to connect to the IP address where `server.py` is running.

