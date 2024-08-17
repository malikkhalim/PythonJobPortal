import shelve

def set_user_as_admin(username):
    db = shelve.open('data.db', writeback=True)
    for user_id, user_data in db['users'].items():
        if user_data['username'] == username:
            db['users'][user_id]['is_admin'] = True
            print(f"User '{username}' is now set as admin.")
            break
    else:
        print(f"User '{username}' not found.")
    db.close()

# Replace 'your_username' with the username you registered
set_user_as_admin('admin') #Replace with your username
