# Port-Scanner

I've crafted a basic port scanner using Python to delve into the capabilities of the nmap tool. This utility empowers users to probe for open ports on a specified host or range of hosts. While it may not employ intricate scanning methodologies, it serves as an entry point for grasping port scanning fundamentals and harnessing the potential of the nmap library.

## Instructions for Usage

1. **Clone the Repository**: Begin by cloning the Git repository using the following command:
`git clone <repository-url>`

2. **Navigate to the Directory**: After cloning, change your directory to the Port-Scanner directory.

3. **Set Up Virtual Environment**: If you're on Windows, create a virtual environment with:
`python -m venv env`
Then, activate the virtual environment using the command:
`env/Scripts/activate.ps1`
If you're using cmd instead of PowerShell, activate the virtual environment with:
  `env/Scripts/activate.bat`
On Linux, create a virtual environment using:
`python3 -m venv env`
Activate it using:
`source myvenv/bin/activate`

4. **Install Dependencies**: Ensure nmap is installed on your system. If not, you can install it from [Nmap](https://nmap.org/). Then, install the necessary Python packages specified in the `requirements.txt` file:
- For Windows:
  ```
  pip install -r requirements.txt
  ```
- For Linux:
  ```
  pip3 install -r requirements.txt
  ```

5. **Run the Port Scanner**: Execute `port_scanner.py` using the command:
   `python port_scanner.py --host localhost --port 21-8000`
   
6. **Example Usage**: Feel free to utilize the port scanner with your desired host and port range. For instance:
 `python port_scanner.py --host localhost --port 1-8000`

Thank you for exploring the Port-Scanner tool!

