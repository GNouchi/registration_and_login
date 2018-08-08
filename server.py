from flask import Flask, render_template, redirect, request, session, flash
from mysqlconnection import connectToMySQL
from flask_bcrypt import Bcrypt
import re, random
app = Flask(__name__)
bcrypt = Bcrypt(app)
NAME_REGEX = re.compile(r'^[a-zA-Z]+$')
EMAIL_REGEX = re.compile(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)")
app.secret_key = "9010B3CEDB7AFC76D550F44776F6DC13DD372498C7B3ED94B264D2254060F9DB"
mysql = connectToMySQL('mydb')
# bcrypt.generate_password_hash(password_string)
# bcrypt.check_password_hash(hashed_password, password_string)

@app.route('/')
def index():
# going to allow a logged user to come here, any entry will reset the authentication process
    # session.clear()
# **********LOGIN PAGE***************
    if 'session_id' in session: 
        return redirect ('/success')
    print (session)
    emaildis = 'Please enter your email address'
    pwd = "I hope you're using unique passwords"
    clr2 ,clr1 = "text-muted" , "text-muted"
# look for flashes
    if '_flashes' in session:
        for x in range(len(session['_flashes'])):
# look for email error 
            if session['_flashes'][x][0] == 'email':
                emaildis = session['_flashes'][x][1]
                clr1 = "red"
# if pwd do not match use flash to display error 
            if session['_flashes'][x][0] == 'pwd':
                pwd =  session['_flashes'][x][1]
                clr2 = "red"
    return render_template("login.html",emaildis=emaildis, pwd = pwd , clr2=clr2 ,clr1= clr1 )    

@app.route("/login" , methods = ["POST"])
def loginfail():
    # print("=== form ===" ,request.form)
    
# Prevent messing with html
# to trigger any of the 2 following messages, html needs to be TAMPERED
    if 'email' not in request.form or request.form['email']=='':
        flash("Please Do Not Edit HTML.", 'email')
    if 'pwd' not in request.form or len(request.form['pwd']) < 12:
        flash("Please Do Not Edit HTML.", 'pwd')
        print(len(request.form['pwd']))

# if HTML has been changed SEND THEM BACK IMMEDIATELY
    if '_flashes' in session:
        if 'fail' not in session: 
            session['fail'] = 0
        session['fail'] += 1
        return redirect ('/') 
    print("start validation")

# **********************************************#
# *********** START LOGIN VALIDATION ***********#
# **********************************************#

# EMAIL & PASS submitted, call server
    if 'pwd' in request.form:
        query = "select id, email, f_name, pwd_enc from userdata where email= %(email)s;"
        data = {
            'email' : request.form['email'] 
            }
        result = mysql.query_db(query, data)

# NO MATCHING email display double errors 
        if result ==():
            flash("We're sorry, your password or email did not match", 'pwd')
            flash("We're sorry, your password or email did not match", 'email')
            if 'fail' not in session: 
                session['fail'] = 0
            session['fail'] += 1
            return redirect ('/')                       
#CORRECT PASSWORD (LOGIN)
        if bcrypt.check_password_hash(result[0]['pwd_enc'], request.form['pwd']):            
            session['first_name'] = result[0]['f_name']
# ROLL before query so that if the query fails randomly, the session will also no longer match
# Also makes it harder to Session Hijack? Maybe?
            session['session_id'] = random.randint(1,1000000000)
            login = "UPDATE userdata SET session_id= %(session_id)s  WHERE email = %(email)s ;"
            insurt = {
                'session_id' : session['session_id']  ,    
                'email': request.form['email']
            }
            zzzzzzzzzz = mysql.query_db(login,insurt)
# remove all failed sessions
            if 'fail' in session:
                session.pop('fail')
            return redirect('success')
#INCORRECT PASSWORD
        else:
            flash("We're sorry, your password or email did not match", 'pwd')
            flash("We're sorry, your password or email did not match", 'email')
            if 'fail' not in session: 
                session['fail'] = 0
            session['fail'] += 1
# not resetting db logged session here because that would log out the correct user
            session['session_id'] = random.randint(1,1000000000)
            return redirect ('/')             
    return redirect ('/')

@app.route('/success', methods=['GET','POST'])
def greatsuccess():
# to check if they just typed in a url 
    if 'session_id' not in session:
        return redirect ('/')
# Checks DB.session_ID vs session.session_ID used to lightly validate current session is not spoofed 
# this method allows persistence of session and robustness of checks e.g(currenttime-update_d)
    query = "select id, session_id from userdata where session_id= %(session_id)s;"
    curr = {
        'session_id' : session['session_id']
    }
    logincheck = mysql.query_db(query, curr)
    print(logincheck)
    print(session['session_id'])
    print(logincheck == ())
# escape no matches
    if logincheck == ():
        session.clear()
        return redirect('/')
    print("now running matching algo")
    print("bool",logincheck[0]['session_id']== session['session_id'])
    print(type(logincheck[0]['session_id']))
    print(type(session['session_id']))
# MATCHING CURRENT SESSION ID VS DB SESSION ID
    if logincheck[0]['session_id']== str(session['session_id']): 
        return render_template ("success.html")        

@app.route('/logout', methods=['POST'])
def loggout():
    session.clear()
    # session.pop('session_id')
    return redirect('/') 

@app.route('/reset', methods=['POST'])        
def RESETSESSION():
    session.clear()
    return redirect('/') 

# *********************************registration*********************************
@app.route('/validate', methods = ['POST'])
def checks():
    arr=['abc', '123','456','qwerty','789', 'pass','p@ss','$$', '00', '11', 'trustno1']
    if 'session_id' in session: 
        return redirect ('/success')
# COVER for BLANK fields
    for key in request.form:
# Flag missing keys (bad)
        if request.form[key]=='':
            flash(key + " missing", 'error')
# STORE ALL non-pw keys in session (this is kinda dangerous)
        if request.form[key] != ''and key!='password' and key!= 'confirm_password' :
            session[key] = request.form[key]
            if request.form[key] not in arr:
                arr.append(request.form[key])          
    # T2 regex on names if not blank (bad)
            if (key=='first_name' or key=='last_name') and not NAME_REGEX.match(request.form[key]):
                flash("Please use only english characters for "+key,'error' )
    # T2 regex on email (bad)
            if key=='email' and not EMAIL_REGEX.match(request.form[key]):
                flash("email is not valid" ,'error' )

# LOOP ENDED, START PW CHECKING (bad)
# check some common passwords + all name entry fields again
    for x in range(len(arr)):       
        if arr[x] in request.form['password']:
            flash("Your password is not secure. Please choose another password" ,'error' )
# check for password match
    if 'password' in request.form and 'confirm_password' in request.form:
        if request.form['password'] != request.form['confirm_password']:
            flash(u'Your password do not match', 'error')
# check for capital and number
    if not (any(x.isupper() for x in request.form['password'])and any(x.isdigit() for x in request.form['password'])):
        flash(u'You must have at least 1 number and 1 Capital letter in your password', 'error')
# remove pii
    arr=['abc', '123','456','qwerty','789', 'pass','p@ss','$$','w0rd', 'trustno1']


# (╯°□°）╯︵ ┻━┻
# Look for ERROR flashes 
    if '_flashes' in session:
        for x in range(len(session['_flashes'])):
            if session['_flashes'][x][0] == 'error':
                print("redirected by error")
                return redirect ('/')
            

# **********************************************#
# ************ START DB VALIDATION *************#
# **********************************************#


#  DOES USER EXIST IN DB?
#  COULD BE MORE SPECIFIC HERE AND LOOK FOR ERROR KEY
# (╯°□°）╯︵ ┻━┻
# Look for ERROR flashes 
    if '_flashes' in session:
        for x in range(len(session['_flashes'])):
            if session['_flashes'][x][0] == 'error':
                print("redirected by error")
                return redirect ('/')
    query = "select id, email from userdata where email= %(email)s;"
    data = {
        'email' : request.form['email'] 
        }
    result = mysql.query_db(query, data)
    for x in result:
        if(x['email'] == request.form['email']):
            print (x)
            flash("This user seems to be registered", 'error')
            return redirect ('/')
        
# explicitly check if user is exists
    if result ==():
        pw_hash = bcrypt.generate_password_hash(request.form['password'])
        session['session_id'] = random.randint(1,1000000000)
        usertoadd = "INSERT INTO userdata (email, f_name, l_name, pwd_enc,session_id, create_d, update_d) VALUES (%(email)s,%(f_name)s,%(l_name)s,%(pwd_enc)s,%(session_id)s, NOW(), NOW());"
        data = {
            'email' : request.form['email'],
            'f_name' : request.form['first_name'],
            'l_name' : request.form['last_name'],
            'pwd_enc' : pw_hash,
            'session_id' : session['session_id']
            }
        adduser = mysql.query_db(usertoadd, data)
        flash(u'Thanks for submitting your information.', 'success')
        return redirect ('success')

    # print('hello')
    # print(request.form)
    # print(session)
    return redirect ('/')



if __name__ == "__main__":
    app.run(debug = True)