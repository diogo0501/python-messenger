import sqlite3

# Connect to the SQLite database
conn = sqlite3.connect('database.db')

# Create a cursor object to execute SQL commands
cursor = conn.cursor()

# Create the users table
cursor.execute('''CREATE TABLE users
                (id INTEGER PRIMARY KEY AUTOINCREMENT,
                 username VARCHAR(30) NOT NULL,
                 password VARCHAR(30) NOT NULL)''')

def populate_users():
    
    for i in range(0,10):
    
        user = ('diogo', 'password')
        cursor.execute('''INSERT INTO users (username,password) VALUES (?,?)''', user)

        # Save (commit) the changes
        conn.commit()


def test_queries():

    cursor.execute('''SELECT * FROM users''')
    users = cursor.fetchall()
    print(users)

populate_users()
test_queries()

# Close the connection
conn.close()
