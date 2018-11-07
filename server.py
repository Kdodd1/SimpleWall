from flask import Flask, render_template, session, request, redirect, flash
from mysqlconnection import connectToMySQL
from flask_bcrypt import Bcrypt 
import re
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
NAME_REGEX = re.compile(r'^[a-zA-Z]*$')
app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = "secret"
    
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/register", methods=['POST'])
def create_account():
	if len(request.form['first_name']) < 2:
		flash("*Name must be at least 2 characters long", "first_name")
	elif not NAME_REGEX.match(request.form['first_name']):
		flash("*Name cannot have special characters or numbers","first_name")

	if len(request.form['last_name']) <2:
		flash("*Name must be at least 2 characters long", "last_name")
	elif not NAME_REGEX.match(request.form['last_name']):
		flash("*Name cannot have special characters or numbers", "last_name")

	mysql = connectToMySQL('simpwalldb')
	emails = mysql.query_db("SELECT email FROM users")
	if not EMAIL_REGEX.match (request.form['email']): 
		flash("*email doesn't follow email format","email")
	
	for email in emails: #check if email input is already in the database

		if request.form['email'] == email['email']:
			flash("*email is already in the database","email")
			return redirect('/')
	if request.form['password'] == '':
		flash("*password field is required", "password")
	elif len(request.form['password']) < 8:
		flash("*password must be greater than 8 characters long", "password")

	if request.form["password_confirmation"] != request.form["password"]:
		flash("*password confirmation doesn't match password", "password_confirmation") 

	if '_flashes' in session.keys():
		return redirect('/')
	else:
		session['email'] = request.form['email']
		pw_hash =bcrypt.generate_password_hash(request.form['password'])
		mysql = connectToMySQL("simpwalldb")
		query = "INSERT INTO users (first_name, last_name, email, password, created_at, updated_at) VALUES (%(first_name)s, %(last_name)s, %(email)s, %(password_hash)s, NOW(),NOW())"
		data = { "first_name" : request.form['first_name'],
				"last_name" : request.form['last_name'],
				"email" : request.form['email'],
				"password_hash" : pw_hash
				}
		mysql.query_db(query, data)
	return redirect("/success")


	return redirect('/success')

@app.route("/login", methods=['POST'])
def login():
	mysql = connectToMySQL('simpwalldb')
	query = "SELECT * FROM users WHERE email = %(email)s"
	data = { "email" : request.form["email_log"]}
	result = mysql.query_db(query, data)
	if result:
		if bcrypt.check_password_hash(result[0]['password'], request.form['password_log']):
			session['email'] = result[0]["email"]
			session['id'] = result[0]["id"]
			session['first_name'] = result[0]["first_name"]
			session['last_name'] = result[0]['last_name']
			print("*"*80)
			print(session["id"])
			return redirect('/success')

	flash("*Email or password is incorrect", "email_log")
	return redirect ('/')
@app.route("/send", methods= ['POST'])
def send():
	mysql = connectToMySQL("simpwalldb")
	query = "INSERT INTO messages (message, senders_id, reciever_id, created_at, updated_at) VALUES (%(message)s, %(senders_id)s, %(reciever_id)s, NOW(),NOW())"
	data = { "message" : request.form['message'],
				"senders_id" : session['id'],
				"reciever_id" : request.form['reciever_id']
				}
	mysql.query_db(query, data)

	return redirect('/success')



@app.route("/success")
def success():
	mysql = connectToMySQL('simpwalldb')
	recieved_messages = mysql.query_db(f"SELECT messages.id, message, messages.created_at, messages.updated_at, first_name, last_name FROM messages LEFT JOIN users ON senders_id = users.id WHERE reciever_id = '{session['id']}'ORDER BY messages.id desc")
	mysql = connectToMySQL('simpwalldb')
	message_chart = mysql.query_db(f"SELECT first_name, id FROM users WHERE id != '{session['id']}' ")
	mysql = connectToMySQL('simpwalldb')
	searchquery = mysql.query_db(f"SELECT message FROM messages LEFT JOIN users ON senders_id = users.id WHERE users.id = '{session['id']}'")
	messages_sent = len(searchquery)

	return render_template("success.html", message_chart = message_chart, recieved_messages = recieved_messages, messages_sent= messages_sent)

@app.route('/delete/<id>')
def delete(id):
	mysql = connectToMySQL('simpwalldb')
	mysql.query_db(f"DELETE FROM messages WHERE id = '{id}';")

	return redirect('/success')

@app.route("/logout")
def logout():
	session.clear()
	return redirect('/')

def debugHelp(message = ""):
    print("\n\n-----------------------", message, "--------------------")
    print('REQUEST.FORM:', request.form)
    print('SESSION:', session)
if __name__ == "__main__":
    app.run(debug=True)