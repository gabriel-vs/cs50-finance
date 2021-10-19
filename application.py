import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

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

    # Some values related to the user that will prove to be useful
    user_name = (db.execute("SELECT username FROM users WHERE id == ?", session["user_id"]))[0]['username']
    user_cash = (db.execute("SELECT cash FROM users WHERE id == ?", session["user_id"]))[0]["cash"]

    # Removes from the database stocks that had all its shares sold
    db.execute("DELETE FROM purchases WHERE shares == ?", 0)

    # Current stocks from the user
    user_purchases = db.execute("SELECT * FROM purchases WHERE username == ?", user_name)

    # These two lines were made just so we can get the total value of all stocks held by the user
    current_prices = {}
    current_prices_added = 0

    for purchase in user_purchases:
        current_prices[purchase["symbol"]] = lookup(purchase["symbol"])["price"]
        current_prices_added += lookup(purchase["symbol"])["price"] * purchase["shares"]

    return render_template("index.html", stocks=user_purchases, current_prices=current_prices, cash=user_cash, current_prices_added=current_prices_added)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    if request.method == "POST":

        # Some values related to the user that will prove to be useful
        user_cash = db.execute("SELECT cash FROM users WHERE id == ?", session["user_id"])[0]["cash"]
        user_name = db.execute("SELECT username FROM users WHERE id == ?", session["user_id"])[0]["username"]

        if not request.form.get("symbol"):
            return apology("No stock was selected", 400)

        # Checks if symbol does exist
        elif lookup(request.form.get("symbol").upper()) == None:
            return apology("invalid stock symbol", 400)

        # Checks if user typed a valid number of shares
        elif not request.form.get("shares") or request.form.get("shares").isnumeric() == False or ".," in str(request.form.get("shares")):
            return apology("invalid number of shares", 400)

        # Checks if number of shares is not negative
        elif float(request.form.get("shares")) < 0:
            return apology("invalid number of shares", 400)

        # Checks if user can afford the purchase
        elif user_cash < lookup(request.form.get("symbol").upper())["price"] * int(request.form.get("shares")):
            return apology("you don't have enough money for this purchase", 400)

        # Update the databases
        else:
            db.execute("INSERT INTO transactions (symbol, shares, price, username) VALUES (?, ?, ?, ?)", request.form.get(
                "symbol").upper(), int(request.form.get("shares")), lookup(request.form.get("symbol").upper())["price"], user_name)

            db.execute("UPDATE users SET cash ==? WHERE id == ?", user_cash - (lookup(request.form.get("symbol").upper())
                                                                               ["price"] * int(request.form.get("shares"))), session["user_id"])

            # Check if user already has this stock. If so, just update the values, but don't insert nothin.
            rows = db.execute("SELECT * FROM purchases WHERE symbol == ? AND username == ?",
                              request.form.get("symbol").upper(), user_name)
            print(rows)
            if len(rows) == 0:
                db.execute("INSERT INTO purchases (symbol, name, shares, price, username) VALUES (?, ?, ?, ?, ?)", request.form.get("symbol").upper(), lookup(
                    request.form.get("symbol").upper())["name"], int(request.form.get("shares")), lookup(request.form.get("symbol").upper())["price"], user_name)
            else:
                db.execute("UPDATE purchases SET shares == ?, price == ? WHERE symbol == ? AND username == ?", rows[0]["shares"] + int(
                    request.form.get("shares")), lookup(request.form.get("symbol").upper())["price"], request.form.get("symbol").upper(), user_name)

            return redirect("/")

    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    # Current user
    user_name = db.execute("SELECT username FROM users WHERE id == ?", session["user_id"])[0]["username"]

    # Get the data related to the transactions made by the current user
    user_transactions = db.execute("SELECT * FROM transactions WHERE username == ?", user_name)

    return render_template("history.html", user_transactions=user_transactions)


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
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

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

    if request.method == "POST":

        if not request.form.get("symbol"):
            return apology("must provide stock symbol", 400)

        symbol = request.form.get("symbol")

        # Checks if symbol does exist
        if lookup(symbol.upper()) == None:
            return apology("invalid stock symbol", 400)

        else:
            return render_template("quoted.html", stock=lookup(symbol.upper()))

    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Checks if user passed all the needed information correctly
        if not request.form.get("username"):
            return apology("must provide username", 400)

        elif not request.form.get("password"):
            return apology("must provide password", 400)

        elif not request.form.get("confirmation"):
            return apology("must confirm password", 400)

        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("passwords do not match", 400)

        elif len(rows) == 1:
            return apology("this username is already being used", 400)

        # Insert user in the database
        else:
            db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", request.form.get("username"),
                       generate_password_hash(request.form.get("password"), method='pbkdf2:sha256', salt_length=8))

        return render_template("login.html")

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    user_name = (db.execute("SELECT username FROM users WHERE id == ?", session["user_id"]))[0]['username']
    user_cash = db.execute("SELECT cash FROM users WHERE id == ?", session["user_id"])[0]["cash"]
    user_purchases = db.execute("SELECT * FROM purchases WHERE username == ?", user_name)

    if request.method == "POST":

        # Checks if user passed a valid stock symbol
        if not request.form.get("symbol"):
            return apology("must provide the stock you want to sell", 400)

        # Get the data related to the stock that user wants to sell
        current_stock = db.execute("SELECT * FROM purchases WHERE username == ? AND symbol == ?",
                                   user_name, request.form.get("symbol"))[0]

        # Checks if user typed a valid number of shares
        if not request.form.get("shares") or request.form.get("shares").isnumeric() == False or ".," in str(request.form.get("shares")):
            return apology("invalid number of shares", 400)

        # Checks if number of shares is not negative
        elif float(request.form.get("shares")) < 0:
            return apology("invalid number of shares", 400)

        # Checks is user has the amount of shares that they want to sell
        elif int(request.form.get("shares")) > int(current_stock["shares"]):
            return apology("you are trying to sell more shares than you own", 400)

        # Update the databases
        else:
            db.execute("INSERT INTO transactions (symbol, shares, price, username) VALUES (?, ?, ?, ?)", request.form.get(
                "symbol").upper(), int(request.form.get("shares")) * -1, lookup(request.form.get("symbol").upper())["price"],  user_name)
            db.execute("UPDATE users SET cash = ? WHERE id = ?", user_cash +
                       ((lookup(request.form.get("symbol").upper())["price"]) * int(request.form.get("shares"))), session["user_id"])
            db.execute("UPDATE purchases SET shares = ? WHERE username = ?", int(
                current_stock["shares"]) - int(request.form.get("shares")), user_name)

            return redirect("/")

    else:
        return render_template("sell.html", stocks=user_purchases)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
