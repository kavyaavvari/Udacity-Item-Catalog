from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from sqlalchemy import create_engine, asc, desc
from sqlalchemy.orm import sessionmaker, scoped_session
from database_setup import Base, User, CatalogItem, Category
from flask import session as login_session
import random
import string

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests


app = Flask(__name__)


CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Item Catalog Application"



#Connect to Database and create database session
engine = create_engine('sqlite:///grocerycatalog.db')
Base.metadata.bind = engine


DBSession = sessionmaker(bind=engine)
session = DBSession()

session = scoped_session(sessionmaker(bind=engine))





# Login required
def must_login(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in login_session:
            return redirect(url_for('showLogin'))
        return f(*args, **kwargs)
    return decorated_function



@app.route('/logged_in')
def logged_in():
    return render_template('logged_in.html')



#form result
@app.route('/result', methods=['POST', 'GET'])
def result():
    if request.method == 'POST':
        result = request.form
        item_name = result['item_name']
        description = result['description']
        price = result['price']
        category = result['category']
        current_user = session.query(User).filter_by(name=login_session['username']).one()
        if session.query(Category).filter_by(name=category).scalar() is None:
            new_Category = Category(name=category, user_id=current_user.id)
            session.add(new_Category)
            session.commit()
            category_id = new_Category.id
        else:
            current_Category = session.query(Category).filter_by(name=category).one()
            category_id = current_Category.id
        groceryCatalog = CatalogItem(name = item_name, description = description, price = price, category_id = category_id, user_id=current_user.id)
        session.add(groceryCatalog)
        session.commit()
    return redirect(url_for('showCatalog'))



#JSON APIs to view Catalog Information
@app.route('/api/catalog/JSON')
def catalogJSON():
    items = session.query(CatalogItem).order_by(CatalogItem.name)
    return jsonify(CatalogItem=[i.serialize for i in items])


@app.route('/api/categories/<int:category_id>/item/<int:catalog_item_id>/JSON')
def catalogItemJSON(category_id, catalog_item_id):
    Catalog_items = session.query(CatalogItem).filter_by(id = catalog_item_id).one()
    return jsonify(Catalog_items = Catalog_items.serialize)


@app.route('/api/categories/JSON')
def categoriesJSON():
    categories = session.query(Category).all()
    return jsonify(allCategories= [r.serialize for r in categories])

@app.route('/catalog.json')
def catalog_detailed():
    categories = session.query(Category).all()
    sel_catalog_items = {}
    for idx, category_i in enumerate(categories):
        sel_catalog_items[idx] = session.query(CatalogItem).filter_by(category_id = category_i.id).all()
    category_json = [r.serialize for r in categories]
    num_categories = len(categories)
    print('CATEGORY JSON')
    print(category_json)
    for idx in range(num_categories):
        category_json[idx]['Item'] = [r.serialize for r in sel_catalog_items[idx]]
    return jsonify(Category=category_json)

#-----------------------------------------------------
#READ = show all categories and latest items
@app.route('/')
@app.route('/categories')
def showCatalog():
    extracted_categories = session.query(Category).all()
    items = session.query(CatalogItem).order_by(asc(CatalogItem.name))
    latest_items = session.query(CatalogItem).order_by(desc(CatalogItem.id)).limit(5).all()
    quantity = items.count()

    if 'username' not in login_session:
        logged_in = False
        return render_template('public_catalog.html', groceries=extracted_categories, logged_in = logged_in, latest_items = latest_items)
    else:
        logged_in = True
        return render_template('catalog.html', groceries=extracted_categories, logged_in = logged_in, latest_items = latest_items)




#CRUD for catalog items
#-----------------------------------------------------
#READ = show catalog items
@app.route('/categories/<int:category_id>/')
@app.route('/categories/<int:category_id>/items/')
def showCatalogItems(category_id):
    extracted_categories = session.query(Category).all()
    category = session.query(Category).filter_by(id = category_id).one()
    items = session.query(CatalogItem).filter_by(category_id = category_id).order_by(CatalogItem.id.desc())
    quantity = items.count()
    if 'username' not in login_session:
        logged_in = False
    else:
        logged_in = True
    return render_template('showcatalogitems.html', selected_grocery = category, groceries = extracted_categories, items = items, quantity = quantity, logged_in=logged_in)



#READ ITEM - show description for that catalog item
@app.route('/categories/<int:category_id>/item/<int:catalog_item_id>/')
def showCatalogItemDescription(category_id, catalog_item_id):
    extracted_categories = session.query(Category).all()
    category = session.query(Category).filter_by(id=category_id).one()
    item = session.query(CatalogItem).filter_by(id=catalog_item_id).one()

    if 'username' not in login_session:
        logged_in = False
    else:
        logged_in = True
    return render_template('catalogitemdescription.html', item=item, selected_grocery = category, groceries = extracted_categories, logged_in=logged_in)




#CREATE - create catalog item
@app.route('/categories/item/new/',methods=['GET','POST'])
@must_login
def newCatalogItem():
  categories = session.query(Category).all()
  logged_in = True
  if request.method == 'POST':
      newItem = CatalogItem(name = request.form['name'], description = request.form['description'], price = request.form['price'], category_id = request.form['category'], user_id = login_session['user_id'])
      session.add(newItem)
      session.commit()
      flash('New %s Catalog Item Successfully Created' % (newItem.name))
      return redirect(url_for('showMenu', restaurant_id = restaurant_id))
  else:
      return render_template('newcatalogitem.html', categories = categories, modification=True, logged_in=logged_in)




#UPDATE - edit catalog item
@app.route('/categories/<int:category_id>/item/<int:catalog_item_id>/edit', methods=['GET','POST'])
@must_login
def editCatalogItem(category_id, catalog_item_id):
    categories = session.query(Category).all()
    category = session.query(Category).filter_by(id = category_id).one()
    editedItem = session.query(CatalogItem).filter_by(id = catalog_item_id).one()
    logged_in = True
    if request.method == 'POST':
        if request.form['item_name']:
            editedItem.name = request.form['item_name']
        if request.form['description']:
            editedItem.description = request.form['description']
        if request.form['price']:
            editedItem.price = request.form['price']
        if request.form['category']:
            selected_category_name = request.form['category']
            if session.query(Category).filter_by(name=selected_category_name).scalar() is None:
                selected_category = Category(name = selected_category_name)
                session.add(selected_category)
                session.commit()
            else:
                selected_category = session.query(Category).filter_by(name=selected_category_name).one()
            editedItem.category = selected_category
            editedItem.category_id = selected_category.id
        session.add(editedItem)
        session.commit()
        flash('Catalog Item Successfully Edited')
        return redirect(url_for('showCatalog'))
    else:
        return render_template('editcatalogitem.html', categories = categories, item = editedItem, selected_grocery = category, modification=True, logged_in=logged_in)



#DELETE - remove a menu item
@app.route('/categories/<int:category_id>/item/<int:catalog_item_id>/delete', methods = ['GET','POST'])
@must_login
def deleteCatalogItem(category_id, catalog_item_id):
    itemToDelete = session.query(CatalogItem).filter_by(id = catalog_item_id).one()
    category = session.query(Category).filter_by(id = category_id).one()
    logged_in = True
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        flash('Catalog Item Successfully Deleted')
        if session.query(CatalogItem).filter_by(category_id=category_id).scalar() is None:
            session.delete(category)
            session.commit()
        else:
            pass
        return redirect(url_for('showCatalog'))
    else:
        return render_template('deletecatalogitem.html', item = itemToDelete, selected_grocery = category, modification=True, logged_in=logged_in)





#LOGIN
#-----------------------------------------------
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in range(32))
    login_session['state'] = state
   # return "The current session state is %s" %login_session['state']
    return render_template('login.html', STATE=state, modification=True)


#Google Login
@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    print("Logged in!")
    login_session['provider'] = 'google'
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response


 # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print("Token's client ID does not match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()
    print(data)
    login_session['username'] = data['email']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print("done!")


    username_list = session.query(User.name).all()
    if login_session['username'] not in username_list:
        new_User = User(name=login_session['username'], email=login_session['email'], picture=login_session['picture'])
        session.add(new_User)
        session.commit()

    return output






 # DISCONNECT - Revoke a current user's token and reset their login_session
@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session.get('access_token')
    if access_token is None:
        print("Access Token is None")
        response = make_response(json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    print('In gdisconnect access token is %s', access_token)
    print('User name is: ')
    print(login_session['username'])
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print('result is ')
    print(result)
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response






# Disconnect based on provider
@app.route('/disconnect')
def disconnect():
    print('within disconnect')
    print(login_session)
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            if 'gplus_id' in login_session:
                del login_session['gplus_id']
            if 'credentials' in login_session:
                del login_session['credentials']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
        if 'username' in login_session:
            del login_session['username']
        if 'email' in login_session:
            del login_session['email']
        if 'picture' in login_session:
            del login_session['picture']
        if 'user_id' in login_session:
            del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.", 'success')
        return redirect(url_for('showCatalog'))
    else:
        flash("You were not logged in", 'danger')
        return redirect(url_for('showCatalog'))




if __name__ == '__main__':
  app.secret_key = 'super_secret_key'
  app.debug = True
  app.run(host = '0.0.0.0', port = 5000)
