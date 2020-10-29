import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd
from datetime import datetime

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    rows = db.execute("SELECT * FROM stocks WHERE userid=?",session["user_id"])
    stocks = []
    for row in rows:
        c = lookup(row["symbol"])
        c["qty"] = row["qty"]
        c["total"] = round(row["qty"] * c["price"],2)
        stocks.append(c)
    cash = db.execute("SELECT cash FROM users WHERE id=?",session["user_id"])[0]["cash"]
    cash = round(cash,2)
    return render_template("home.html",stocks=stocks,cash=cash)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "GET":
        return render_template("buy_stocks.html")
    symbol = request.form.get("symbol")
    shares = int(request.form.get("shares"))

    stock_data = lookup(symbol)
    if stock_data == None:
        return apology("symbol doesn't exist")
    #TODO chekc the amount of money user has
    query_res = db.execute("SELECT cash FROM users WHERE id=?",session["user_id"])
    if len(query_res) == 0:
        return apology("user no longer exists")
    cash_left = query_res[0]["cash"]
    if cash_left < (shares * stock_data["price"]):
        return apology("You don't have enough funds to purchase the stock")

    total_amount = shares * stock_data["price"]
    total_amount = round(total_amount,2)
    description = f"bought {shares} {stock_data['name']} share(s) for ${total_amount}"
    print(description)
    res = db.execute("""
        INSERT INTO transactions (
            description,
            date,
            amount,
            userid,
            qty,
            symbol
        ) VALUES (?,strftime('%s','now'),?,?,?,?)
        """,description,stock_data["price"],session["user_id"],shares,symbol.upper())
    res = db.execute("SELECT * FROM (SELECT * FROM stocks WHERE userid=?) WHERE symbol=?",session["user_id"],symbol.upper())
    print(res)
    if len(res) == 0:
        db.execute("INSERT INTO stocks (symbol,qty,userid) VALUES(?,?,?)",symbol.upper(),shares,session["user_id"])
    else:
        db.execute("UPDATE stocks SET qty=? WHERE id=?",res[0]["qty"]+shares,res[0]["id"])
    res = db.execute("UPDATE users SET cash=? WHERE id=?",cash_left-total_amount,session["user_id"])


    return redirect("/")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    rows = db.execute("SELECT symbol,qty,amount,description,date FROM transactions WHERE userid=? ORDER BY date DESC",session["user_id"])
    return render_template("history.html",rows=rows)


@app.template_filter('cvt_time')
def convertTime(t):
    return datetime.fromtimestamp(t).strftime("%A, %B %d, %Y %I:%M:%S")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "GET":
        return render_template("quote.html")
    name = request.form.get("symbol")
    if not name:
        return apology("symbol can not be blank")
    res = lookup(name)
    if res == None:
        return apology("could not find symbol")
    return render_template("quoted.html",data=res)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "GET":
        return render_template("signup.html")
    username = request.form.get("username")
    password = request.form.get("password")
    password1 = request.form.get("confirm-password")

    if password1 != password:
        return apology("passwords must match")
    rows = db.execute("SELECT * FROM users WHERE username=?",username)
    if len(rows) != 0:
        return apology("username has already been taken")

    res = db.execute("INSERT INTO users (username,hash) VALUES(?,?)",username,generate_password_hash(password))
    if res == None:
        return apology("failed to register user, try again")
    return redirect("/login")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    stocks = db.execute("SELECT id,qty,symbol FROM stocks WHERE userid=?",session["user_id"])
    if request.method == "GET":
        return render_template("sell_stocks.html",symbols=stocks)
    symbol = request.form.get("symbol")
    qty = int(request.form.get("shares"))
    if symbol == "select" or not qty:
        return apology("fields must be filled")

    #bad code next time query db or something
    rm = 0
    stock_id = None
    for stock in stocks:
        if stock["symbol"] == symbol:
            rm = stock["qty"]
            stock_id = stock["id"]
            if stock["qty"] < int(qty):
                return apology("you can't sell more than you have")

    stock_data = lookup(symbol)
    total_amount = round(qty * stock_data["price"],2)
    description = f"sold {qty} {stock_data['name']} share(s) for ${total_amount}"

    res = db.execute("""
        INSERT INTO transactions (
            description,
            date,
            amount,
            userid,
            qty,
            symbol
        ) VALUES (?,strftime('%s','now'),?,?,?,?)
        """,description,stock_data["price"],session["user_id"],-1*qty,symbol.upper())

    if rm - qty != 0:
        db.execute("UPDATE stocks SET qty=? WHERE id=?",rm-qty,stock_id)
    else:
        db.execute("DELETE FROM stocks WHERE id=?",stock_id)

    cash = db.execute("SELECT cash FROM users WHERE id=?",session["user_id"])[0]["cash"]
    db.execute("UPDATE users SET cash=? WHERE id=?",round(cash + total_amount,2),session["user_id"])
    return redirect('/')

@app.route('/change_pass',methods=['GET','POST'])
@login_required
def change_password():
    if request.method == "GET":
        return render_template("change_password.html")

    current_password = request.form.get("old-pass")
    new_password = request.form.get("new-pass")
    con_new_password = request.form.get("confirm-new-pass")

    if new_password != con_new_password:
        return apology("passwords must match")

    p_hash = db.execute("SELECT hash FROM users WHERE id=?",session["user_id"])[0]["hash"]

    if not check_password_hash(p_hash,current_password):
        return apology("enter the correct current password")
    db.execute("UPDATE users SET hash=? WHERE id=?",generate_password_hash(new_password),session["user_id"])
    return redirect('/')

def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
