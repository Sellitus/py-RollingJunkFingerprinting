class Message:
    full_command = ""   # Original command before parsing
    sender = ""         # Person who originally sent the message
    data = ""           # Data string (arguments + data after initial /<command> )
    request_type = ""   # Type of request (/upload, /download, /list, /history )


    # The class "constructor" - It's actually an initializer
    def __init__(self, full_command, sender):
        self.full_command = full_command
        self.sender = sender

        pieces = full_command.split(" ")

        if pieces[0][0] == "/":
            request_type = pieces[0][1:].lower()
            self.request_type = request_type

            temp_data = ""
            for i in range(1,pieces.__len__()):
                if temp_data == "":
                    temp_data = pieces[i]
                else:
                    temp_data = temp_data + " " + pieces[i]

            self.data = temp_data

            if request_type == "ls" or request_type == "dir":   # Lists the files in
                i = 0
            elif request_type == "upload":      # Upload file listed after /upload command
                i = 0
            elif request_type == "download":    # Download file listed after /download command
                i = 0
            elif request_type == "history":     # Message/user command history
                i = 0


def create_message(full_command, sender):
    message = Message(full_command, sender)
    return message