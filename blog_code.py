from flask import render_template, redirect, url_for
from flask_login import current_user
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, Length
from flask_ckeditor import CKEditorField
from datetime import date

class BlogPostForm(FlaskForm):
    title = StringField("Title", validators=[DataRequired(), Length(max=200)])
    subtitle = StringField("Subtitle", validators=[DataRequired(), Length(max=200)])
    content = CKEditorField("Content", validators=[DataRequired()])
    submit = SubmitField("Publish Post")


class BlogManager:
    def __init__(self, app, db, blog_posts):
        self.app = app
        self.db = db
        self.blog_posts = blog_posts

    def view_blog_posts(self):
        posts = self.blog_posts.query.order_by(self.blog_posts.date.desc()).all()
        return render_template("blog.html", posts=posts)

    def create_blog_post(self):
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
            
        if current_user.coach_status != 1:  # Admin check
            return redirect(url_for('home_page'))
        
        form = BlogPostForm()
        if form.validate_on_submit():
            new_post = self.blog_posts(
                title=form.title.data,
                subtitle=form.subtitle.data,
                content=form.content.data,
                date=date.today(),
                author_id=current_user.id
            )
            self.db.session.add(new_post)
            self.db.session.commit()
            return redirect(url_for('view_blog_posts'))
            
        return render_template("create_blog_post.html", form=form)

    def view_blog_post(self, post_id, title):
        post = self.blog_posts.query.get_or_404(post_id)
        
        url_title = post.title.lower().replace(' ', '-')
        if title != url_title:
            return redirect(url_for('view_blog_post', post_id=post_id, title=url_title))
        
        total_posts = self.blog_posts.query.count()
        all_posts = self.blog_posts.query.order_by(self.blog_posts.date.asc()).all()
        current_post_index = all_posts.index(post)
        
        is_older_half = current_post_index < total_posts / 2
        
        if is_older_half:
            related_posts = self.blog_posts.query.order_by(self.blog_posts.date.desc()).limit(6).all()
        else:
            related_posts = self.blog_posts.query.order_by(self.blog_posts.date.asc()).limit(6).all()
        
        related_posts = [p for p in related_posts if p.id != post_id][:5]
        
        return render_template("blog_post.html", post=post, related_posts=related_posts)