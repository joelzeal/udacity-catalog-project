from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Base, Category, CategoryItem, User

engine = create_engine('sqlite:///catalogitemswithusers.db')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
session = DBSession()


# Create dummy user
User1 = User(name="Joel Zeal", email="joelzeal@gmail.com",
             picture='https://pbs.twimg.com/profile_images/2671170543/18debd694829ed78203a5a36dd364160_400x400.png')
session.add(User1)
session.commit()

# Item for UrbanBurger
category1 = Category(user_id=1, name="Soccer")

session.add(category1)
session.commit()

categoryItem1 = CategoryItem(user_id=1, name="Jersey",category=category1, description="some description goes here. some description goes here...")

session.add(categoryItem1)
session.commit()

categoryItem2 = CategoryItem(user_id=1, name="Soccer Cleates",category=category1, description="some description goes here. some description goes here...")

session.add(categoryItem2)
session.commit()


categoryItem3 = CategoryItem(user_id=1, name="Gloves",category=category1, description="some description goes here. some description goes here...")

session.add(categoryItem3)
session.commit()
print "added menu items!"