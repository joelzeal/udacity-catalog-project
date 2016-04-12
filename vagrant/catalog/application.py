from flask import Flask, render_template, request, redirect, jsonify, url_for, flash
from flask.ext.seasurf import SeaSurf
from functools import wraps
from sqlalchemy import create_engine, asc, desc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, CategoryItem, User
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
csrf = SeaSurf(app)


CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Restaurant Menu Application"


# Connect to Database and create database session
engine = create_engine('sqlite:///catalogitemswithusers.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()



def login_required(fn):
    @wraps(fn)
    def wrap(*args, **kwargs):
        try:
            if login_session:
                print 'login_exits'
                if 'username' not in login_session:
                    return redirect(url_for('showlogin'))
                else:
                    return fn(*arg, **kwargs)
            else:
                return redirect(url_for('showlogin'))
        except KeyError, e:
            print e
            return redirect(url_for('showlogin'))
    return wrap

def isobjectowner(user_id):
    if getUserID(login_session['email']) ==  user_id:
        return True
    else:
        return False 

# Routes
# Create anti-forgery state token
@app.route('/login')
def showLogin():
    """
    Create anti-forgery state token and render login template.
    :return: rendered template
    """
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)


@csrf.exempt
@app.route('/gconnect', methods=['POST'])
def gconnect():
    """
    Perform google oauth authentication and trade access_token
    for user credentials.
    :Param: None:
    :return: String
    """
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
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
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    # login_session['credentials'] = credentials
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 200px; height: 200px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    # check if user exists
    #user_id = getUserID(login_session['email']).one()
    # if not user_id:
    #    user_id = createUser(login_session)
    # login_session['user_id']
    return output


@csrf.exempt
@app.route('/gdisconnect')
def gdisconnect():
    """
    Disconnects from google account and deletes 
    for the login_session object.
    :params: None
    :return: rendered login template
    """
    access_token = login_session['access_token']
    print 'In gdisconnect access token is %s', access_token
    print 'user name is: '
    print login_session['username']
    if access_token is None:
        print 'Access Token is None'
        response = make_response(json.dumps(
            'Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print 'result is '
    print result
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        print response
        return render_template('/login.html')
    else:
        response = make_response(json.dumps(
            'Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return render_template('/login.html')


def createUser(login_session):
    """
    Create new user with details from the login session
    :param login_session: dictionary containing currently logged
    in user's information.
    :return int: new user's id
    """
    new_user = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(new_user)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    """
    Get user info by id.
    :param user_id: user id to filter by.
    :return object: user who's id was passed
    """
    user = session.query(User).get(user_id)
    return user


def getUserID(email):
    """
    Get user by email.
    :param email: email address to filter by.
    :return int: user's id
    """
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


# Categories
@login_required
@app.route('/')
def showDashboard():
    """
    validates user is logged in and displays top 20 recently
    added category items. 
    :param: None
    :return: rendered template.
    """
    if 'username' not in login_session:
        return redirect(url_for('showLogin'))
    else:
        categories = session.query(Category).order_by(asc(Category.name))
        category_items = session.query(CategoryItem).order_by(
            desc(CategoryItem.id)).limit(20)
        return render_template('dashboard.html', title='Dashboard', categories=categories, items=category_items,
                               username=login_session['username'], profile_picture=login_session['picture'])


# Show categories
@app.route('/categories/')
def showCategories():
    """
    validates user is logged in and displays all categories 
    :param: None
    :return: rendered template.
    """
    if 'username' not in login_session:
        return redirect(url_for('showLogin'))
    else:
        categories = session.query(Category).order_by(asc(Category.name))
        return render_template('categories_main.html', categories=categories, title='Categories',
                               username=login_session['username'], profile_picture=login_session['picture'], isobjectowner=isobjectowner)


# create a new Category
@app.route('/category/new/', methods=['GET', 'POST'])
def newCategory():
    """
    validates user is logged in and creates a new category 
    :param: None
    :return: rendered template.
    """
    if 'username' not in login_session:
        return redirect('/login')
    else:
        categories = session.query(Category).order_by(asc(Category.name))
        if request.method == 'POST':
            newcategory = Category(name=request.form['name'])
            session.add(newcategory)
            session.commit()
            return redirect(url_for('showCategories'))
        else:
            return render_template('newCategory.html', categories=categories, title='New Category',
                                   username=login_session['username'], profile_picture=login_session['picture'])


# Edit a Category
@app.route('/category/<int:category_id>/edit/', methods=['GET', 'POST'])
def editCategory(category_id):
    """
    validates user is logged in and updates edited category 
    :param category_id: category id to filter by
    :return: rendered template.
    """
    if 'username' not in login_session:
        return redirect('/login')
    else:
        categories = session.query(Category).order_by(asc(Category.name))
        edited_category = session.query(
            Category).get(category_id)
        if request.method == 'POST':
            if request.form['name']:
                edited_category.name = request.form['name']
                flash('Category Successfully Edited %s' % edited_category)
                session.commit()
                return redirect(url_for('showCategories'))
        else:
            return render_template('editCategory.html', category=edited_category,
                                   categories=categories, username=login_session[
                                       'username'],
                                   profile_picture=login_session['picture'], title='Edit Category')


# Delete a Category
@app.route('/category/<int:category_id>/delete/', methods=['GET', 'POST'])
def deleteCategory(category_id):
    """
    validates user is logged in and deletes a category 
    :param category_id: category id to filter by.
    :return: rendered template.
    """
    if 'username' not in login_session:
        return redirect('/login')
    else:
        categories = session.query(Category).order_by(asc(Category.name))
        category_to_delete = session.query(
            Category).get(category_id)
        if request.method == 'POST':
            session.delete(category_to_delete)
            flash('%s Successfully Deleted' % category_to_delete.name)
            session.commit()
            return redirect(url_for('showCategories'))
        else:
            return render_template('deleteCategory.html', category=category_to_delete, categories=categories,
                                   username=login_session['username'], profile_picture=login_session['picture'],
                                   isobjectowner=isobjectowner, title='Delete Category')


# Show Category items
@app.route('/category/<int:category_id>/')
@app.route('/category/<int:category_id>/items/')
def showItems(category_id):
    """
    validates user is logged in and displays all category
    items.
    :param: category_id
    :return: rendered template.
    """
    if 'username' not in login_session:
        return redirect('/login')
    else:
        categories = session.query(Category).order_by(asc(Category.name))
        category = session.query(Category).get(category_id)
        return render_template('categoryItems.html', items=category.items,
                               category=category, categories=categories, username=login_session[
                                   'username'],
                               profile_picture=login_session['picture'], title='Show Categories',
                               isobjectowner=isobjectowner)


# Create a new menu item
@app.route('/category/<int:category_id>/item/new/', methods=['GET', 'POST'])
def newCategoryItem(category_id):
    """
    validates user is logged in and creates a new category item
    as a child of the selected category.  
    :param category_id: parent category
    :return: rendered template.
    """
    if 'username' not in login_session:
        return redirect('/login')
    else:
        categories = session.query(Category).order_by(asc(Category.name))
        parent_category = session.query(
            Category).get(category_id)
        if request.method == 'POST':
            if request.form['name'] and request.form['description']:
                category_item = CategoryItem(name=request.form['name'],
                                            description=request.form['description'], category=parent_category)
                session.add(parent_category)
                session.commit()
                flash('%s Successfully fully added' % parent_category.name)
                return redirect(url_for('showItems', category_id=category_id))
        else:
            return render_template('newCategoryItem.html', category=parent_category,
                                   categories=categories, username=login_session[
                                       'username'],
                                   profile_picture=login_session['picture'], title='New Item')


# Show category item details
@app.route('/category/<int:category_id>/item/<int:item_id>')
def showCategoryItemDetails(category_id, item_id):
    """
    validates user is logged in and displays all category item details 
    :param category_id: parent category id.
    :param item_id: id of the category item to display.
    :return: rendered template.
    """
    if 'username' not in login_session:
        return redirect('/login')
    else:
        categories = session.query(Category).order_by(asc(Category.name))
        parent_category = session.query(
            Category).get(category_id)
        category_item = session.query(CategoryItem).filter_by(
            category_id=category_id, id=item_id).one()
        return render_template('categoryItemDetails.html', category=parent_category,
                               categoryItem=category_item, categories=categories,
                               username=login_session['username'], profile_picture=login_session['picture'], 
                               title='Item Details', isobjectowner=isobjectowner)


# Edit Category item
@app.route('/category/<int:category_id>/item/<int:item_id>/edit', methods=['GET', 'POST'])
def editCategoryItem(category_id, item_id):
    """
    validates user is logged in and edits selected category item 
    :param category_id: parent category
    :param item_id: category item to edit
    :return: rendered template.
    """
    if 'username' not in login_session:
        return redirect('/login')
    else:
        categories = session.query(Category).order_by(asc(Category.name))
        category_item_to_edit = session.query(CategoryItem).filter_by(
            category_id=category_id, id=item_id).one()
        if request.method == 'POST':
            if request.form['name']:
                category_item_to_edit.name = request.form['name']
                category_item_to_edit.description = request.form['description']
                flash('Item Successfully updated')
                session.commit()
                return redirect(url_for('showItems', category_id=category_id))
        else:
            return render_template('editCategoryItem.html', item=category_item_to_edit, categories=categories,
                                   username=login_session['username'], profile_picture=login_session['picture'], 
                                   title='Edit Item', isobjectowner=isobjectowner)


# Delete Category item
@app.route('/category/<int:category_id>/item/<int:item_id>/delete', methods=['GET', 'POST'])
def deleteCategoryItem(category_id, item_id):
    """
    validates user is logged in and deletes selected category item.
    :param category_id: parent category
    :param item_id: category item to delete
    :return: rendered template.
    """
    if 'username' not in login_session:
        return redirect('/login')
    else:
        categories = session.query(Category).order_by(asc(Category.name))
        category_item_to_delete = session.query(CategoryItem).filter_by(
            id=item_id, category_id=category_id).one()
        if request.method == 'POST':
            session.delete(category_item_to_delete)
            flash('%s Successfully Deleted' % category_item_to_delete.name)
            session.commit()
            return redirect(url_for('showItems', category_id=category_id))
        else:
            return render_template('deleteCategoryItem.html', item=category_item_to_delete,
                                   categories=categories, username=login_session[
                                       'username'],
                                   profile_picture=login_session['picture'], 
                                   title='Delete Category Item', isobjectowner=isobjectowner)


# json endpoints
@app.route('/json')
@app.route('/dashboard/json')
def showDashboardJSON():
    """
    Json endpoint to display dashboard items.
    :param: None
    :return: json output.
    """
    category_items = session.query(CategoryItem).order_by(
        desc(CategoryItem.id)).limit(20)
    return jsonify(recentlyAddedItems=[i.serialize for i in category_items])


@app.route('/categories/json')
def showCategoriesJson():
    """
    Json endpoint to display all categories.
    :param: None
    :return: json output.
    """
    categories = session.query(Category).order_by(asc(Category.name))
    return jsonify(categories=[i.serialize for i in categories])


@app.route('/category/<int:category_id>/json')
@app.route('/category/<int:category_id>/items/json')
def showItemsJson(category_id):
    """
    Json endpoint to display selected category items .
    :param category_id: selected category
    :return: json output.
    """
    category_items = session.query(
        CategoryItem).get(category_id)
    return jsonify(categoryItems=[i.serialize for i in category_items])


@app.route('/category/<int:category_id>/item/<int:item_id>/json')
def showCategoryItemDetailsJson(category_id, item_id):
    """
    Json endpoint to display selected category item's details .
    :param category_id: selected category.
    :param item_id: item to display.
    :return: json output.
    """
    category_item = session.query(CategoryItem).filter_by(
        category_id=category_id, id=item_id).one()
    return jsonify(categoryItems=[category_item.serialize])


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
