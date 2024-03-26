import tkinter as tk

def send_message():
    eval("turnadmin('{}')".format(entry.get()))
    # Here you can define what to do with the message, for example, print it

def printExp():
    print("Exploitt")
    
def turnadmin(admin):
    print("The admin is " + admin)

# Create the main window
root = tk.Tk()
root.title("Message Sender")

# Create a text box
entry = tk.Entry(root, width=50)
entry.pack(pady=10)

# Create a button to send the message
send_button = tk.Button(root, text="Send", command=send_message)
send_button.pack()
# Run the Tkinter event loop
root.mainloop()



# secret_number = random.randint(1,500)
# print ("Pick a number between 1 to 500")





# while True:
#     res = eval(input("Guess the number: "))
#     if res==secret_number:
#         print ("You win")
#         break
#     else:
#         print ("You lose")
#         continue

