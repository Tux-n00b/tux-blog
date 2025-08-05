import React, { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import ReactMarkdown from 'react-markdown';
import { format } from 'date-fns';
import { BlogPost } from '../types/blog';
import { getMarkdownContent } from '../utils/markdownLoader';
import './Post.css';

const Post: React.FC = () => {
  const { slug } = useParams<{ slug: string }>();
  const [post, setPost] = useState<BlogPost | null>(null);
  const [content, setContent] = useState<string>('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string>('');

  useEffect(() => {
    const loadPost = async () => {
      try {
        setLoading(true);
        setError('');

        const response = await fetch(`${process.env.PUBLIC_URL}/data/blogIndex.json`);
        const postsData: BlogPost[] = await response.json();
        const foundPost = postsData.find((p) => p.slug === slug);

        if (!foundPost) {
          throw new Error('Post not found in index');
        }

        setPost(foundPost);

        const markdownContent = await getMarkdownContent(foundPost.filename);
        setContent(markdownContent);

        setLoading(false);
      } catch (err) {
        console.error('Error loading post:', err);
        setError('Failed to load post. GitHub Pages may still be syncing. Please try again.');
        setLoading(false);
      }
    };

    if (slug) {
      loadPost();
    }
  }, [slug]);

  if (loading) {
    return (
      <div className="post-page">
        <div className="container">
          <div className="loading">
            <div className="loading-spinner"></div>
            <p>Loading post...</p>
          </div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="post-page">
        <div className="container">
          <div className="error">
            <h1>Error Loading Post</h1>
            <p>{error}</p>
            <Link to="/blog" className="btn">← Back to Blog</Link>
          </div>
        </div>
      </div>
    );
  }

  if (!post) return null;

  return (
    <div className="post-page">
      <div className="container">
        <article className="post-content">
          <header className="post-header">
            <nav className="post-nav">
              <Link to="/blog" className="back-link">← Back to Blog</Link>
            </nav>

            <h1 className="post-title">{post.title}</h1>

            <div className="post-meta">
              <time className="post-date">
                {format(new Date(post.date), 'MMMM dd, yyyy')}
              </time>
              <div className="post-tags">
                {post.tags.map((tag, i) => (
                  <span key={i} className="tag">#{tag}</span>
                ))}
              </div>
            </div>

            <p className="post-description">{post.description}</p>
          </header>

          <div className="post-body">
            <ReactMarkdown
              components={{
                img: ({ src = '', alt = '' }) => (
                  <img
                    src={src.startsWith('http') ? src : `${process.env.PUBLIC_URL}${src}`}
                    alt={alt}
                    style={{ maxWidth: '100%' }}
                  />
                )
              }}
            >
              {content}
            </ReactMarkdown>
          </div>

          <footer className="post-footer">
            <div className="post-navigation">
              <Link to="/blog" className="btn">← Back to Blog</Link>
            </div>
          </footer>
        </article>
      </div>
    </div>
  );
};

export default Post;
