import os
import re
import random
import hashlib
import hmac
import time
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

secret = 'fart'


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)


class MainPage(BlogHandler):
    def get(self):
        self.write('Hello, Udacity!')


# user stuff
def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


def users_key(group='default'):
    return db.Key.from_path('users', group)


class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


# blog stuff

def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    created_by = db.StringProperty(required=False)
    last_modified = db.DateTimeProperty(auto_now=True)
    likes = db.IntegerProperty(required=True)
    liked_by = db.ListProperty(str)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)


class Comment(db.Model):
    content = db.TextProperty(required=True)
    post = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    created_by = db.StringProperty(required=False)
    last_modified = db.DateTimeProperty(auto_now=True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("newcomment.html", c=self)


class BlogFront(BlogHandler):
    def get(self):
        posts = greetings = Post.all().order('-created')
        self.render('front.html', posts=posts)


class PostPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("postpage.html", post=post)


class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/login')

        subject = self.request.get('subject')
        content = self.request.get('content')
        created_by = self.user.name

        if subject and content:
            p = Post(
                parent=blog_key(),
                subject=subject,
                content=content,
                created_by=created_by,
                likes=0,
                liked_by=[])
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject,
                        content=content, error=error)


class Rot13(BlogHandler):
    def get(self):
        self.render('rot13-form.html')

    def post(self):
        rot13 = ''
        text = self.request.get('text')
        if text:
            rot13 = text.encode('rot13')

        self.render('rot13-form.html', text=rot13)


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_email(email):
    return not email or EMAIL_RE.match(email)


class Signup(BlogHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError


class Unit2Signup(Signup):
    def done(self):
        self.redirect('/unit2/welcome?username='+self.username)


class Register(Signup):
    def done(self):
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()
            self.login(u)
            self.redirect('/blog')


class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error=msg)


class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/blog')


class Delete(BlogHandler):
    def get(self):
        post_id = self.request.get("post")
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if not self.user != post.created_by:
            self.redirect('/blog')

        self.render("delete.html", post=post)

    def post(self):
        if self.user:
            post_id = self.request.get("post")
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if self.user.name == post.created_by:
                db.delete(key)
                self.redirect('/blog')
            else:
                error = "You do not have permission to delete this post"
                self.render("delete.html", post=post, error=error)
        else:
            self.redirect('/login')


class Edit(BlogHandler):
    def get(self):
        post_id = self.request.get("post")
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if not self.user != post.created_by:
            self.redirect('/blog')
        subject = post.subject
        content = post.content
        if not post:
            self.error(404)
            return

        self.render("newpost.html", subject=subject, content=content)

    def post(self):
        post_id = self.request.get("post")
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        subject = self.request.get('subject')
        content = self.request.get('content')

        if not self.user:
            error = "You do not have permission to edit this post"
            self.render("newpost.html",
                        subject=subject, content=content, error=error)

        elif not self.user.name == post.created_by:
            error = "You do not have permission to edit this post"
            self.render("newpost.html", error=error)

        elif subject and content:
            post.subject = subject
            post.content = content
            post.put()
            self.redirect('/blog/%s' % str(post.key().id()))

        else:
            error = "subject and content, please!"
            self.render("newpost.html",
                        subject=subject, content=content, error=error)


class CommentPage(BlogHandler):
    def get(self):
        if not self.user:
            error = "You must be logged in to comment on posts"
            self.redirect('/login')

        post_id = self.request.get("post")
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if not post:
            self.error(404)

        comments = db.GqlQuery(
            "select * from Comment where post = :1 order by created desc",
            post_id)

        self.render("comment.html", post=post,
                    comments=comments, post_id=post_id)

    def post(self):
        if not self.user:
            self.redirect('/login')
        post_id = self.request.get("post")
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        content = self.request.get('addComment')
        created_by = self.user.name
        if not post:
            self.error(404)

        elif not content:
            error = "content, please!"
            query = """
            select * from Comment where post = :1 order by created desc
            """
            comments = db.GqlQuery(query, post_id)
            self.render("comment.html", post=post,
                        comments=comments, post_id=post_id, error=error)

        else:
            c = Comment(content=content, post=post_id, created_by=created_by)
            c.put()
            query = """
            select * from Comment where post = :1 order by created desc
            """
            comments = db.GqlQuery(query, post_id)
            self.render("comment.html", post=post,
                        comments=comments, post_id=post_id)


class EditComment(BlogHandler):
    def get(self):
        comment_id = self.request.get("comment")
        comment = Comment.get_by_id(int(comment_id))
        if not self.user:
            self.redirect('/login')
        elif not self.user.name == comment.created_by:
            self.redirect('/login')

        self.render("editcomment.html", comment=comment.content)

    def post(self):
        comment_id = self.request.get("comment")
        comment = Comment.get_by_id(int(comment_id))
        content = self.request.get('editComment')

        if not self.user:
            error = "You do not have permission to edit this post"
            self.render("editcomment.html",
                        comment=comment.content, error=error)

        elif not self.user.name == comment.created_by:
            error = "You do not have permission to edit this post"
            self.render("editcomment.html",
                        comment=comment.content, error=error)

        elif content:
            comment.content = content
            comment.put()
            self.redirect('/blog/comments?post=%s' % str(comment.post))

        else:
            error = "Comment cannot be blank"
            self.render("editcomment.html",
                        comment=comment.content, error=error)


class DeleteComment(BlogHandler):
    def get(self):
        comment_id = self.request.get("comment")
        comment = Comment.get_by_id(int(comment_id))
        if not self.user:
            self.redirect('/login')
        elif not self.user.name == comment.created_by:
            self.redirect('/login')
        self.render("deletecomment.html", comment=comment)

    def post(self):
        comment_id = self.request.get("comment")
        comment = Comment.get_by_id(int(comment_id))
        if self.user.name == comment.created_by:
            db.delete(comment)
            self.redirect('/blog/comments?post=%s' % str(comment.post))
        else:
            error = "You do not have permission to delete this post"
            self.render("deletecomment.html", comment=comment, error=error)


class ResetLikes(BlogHandler):
    def get(self):
        posts = greetings = Post.all()
        for p in posts:
            if not p.likes:
                p.likes = 0
                p.liked_by = []
                p.put()


class LikePost(BlogHandler):
    def get(self):
        post_id = self.request.get("post")
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if not self.user:
            self.redirect('/login')
        elif self.user.name == post.created_by:
            error = "You cannot like your own post"
            self.render("error.html", error=error)
        elif self.user.name in post.liked_by:
            error = "You already liked this post"
            self.render("error.html", error=error)
        else:
            user_liked = self.user.name
            post.likes += 1
            post.liked_by.append(user_liked)
            post.put()
            self.redirect("/blog")


class UnlikePost(BlogHandler):
    def get(self):
        post_id = self.request.get("post")
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if not self.user:
            self.redirect('/login')
        elif self.user.name == post.created_by:
            error = "You cannot unlike your own post"
            self.render("error.html", error=error)
        elif self.user.name not in post.liked_by:
            error = "You have not yet liked this post"
            self.render("error.html", error=error)
        else:
            user_unliked = self.user.name
            post.likes -= 1
            post.liked_by.remove(user_unliked)
            post.put()
            self.redirect("/blog")


class Unit3Welcome(BlogHandler):
    def get(self):
        if self.user:
            self.render('welcome.html', username=self.user.name)
        else:
            self.redirect('/signup')


class Welcome(BlogHandler):
    def get(self):
        username = self.request.get('username')
        if valid_username(username):
            self.render('welcome.html', username=username)
        else:
            self.redirect('/unit2/signup')


app = webapp2.WSGIApplication([('/blog', MainPage),
                               ('/unit2/rot13', Rot13),
                               ('/unit2/signup', Unit2Signup),
                               ('/unit2/welcome', Welcome),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/blog/delete', Delete),
                               ('/blog/edit', Edit),
                               ('/blog/comments', CommentPage),
                               ('/blog/editcomment', EditComment),
                               ('/blog/deletecomment', DeleteComment),
                               ('/blog/like', LikePost),
                               ('/blog/unlike', UnlikePost),
                               ('/blog/resetlikes', ResetLikes),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ],
                              debug=True)
