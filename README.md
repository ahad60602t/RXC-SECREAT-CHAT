IRC Secret Chat Application
Description
The IRC Secret Chat Application is a simple chat application built using Python's tkinter library for the GUI and includes basic chat functionalities such as joining chats, sending messages, and admin controls.

Features
User Registration: Users can register with a username, nickname, and join a specific channel.
Join Chat: Users can join different channels based on their registration.
Admin Panel: Admins can manage users, start/stop the server, and view active users.
File Transfer: Ability to send files during a chat session.
Installation
Clone the repository:

bash
Copy code
git clone https://github.com/your_username/irc-secret-chat.git
cd irc-secret-chat
Install dependencies (if any):

bash
Copy code
# Ensure you have Python installed (Python 3.6+ recommended)
# If using virtual environments:
python -m venv venv
source venv/bin/activate  # On Windows use `venv\Scripts\activate`
pip install -r requirements.txt
Usage
Run the application:

bash
Copy code
python irc_secret_chat.py
User Registration:

Click on the "Register" button to register with a username, nickname, and select a channel.
Join Chat:

Enter your username and the generated key to join a specific channel.
Admin Controls:

Click on "Admin Login" to access admin controls.
Manage users (block, unblock, mute, unmute, remove).
Start and stop the server.
Chatting:

Type your message in the message box and click "Send" to send a message.
Use the "Send File" button to send files during a chat session.
Contributing
Contributions are welcome! Please fork the repository and create a pull request with your improvements.
