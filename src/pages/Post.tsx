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
        
      // Load post metadata
      const response = await fetch(`${process.env.PUBLIC_URL}/data/blogIndex.json`);
      const postsData: BlogPost[] = await response.json();
      const postData = postsData.find((p: BlogPost) => p.slug === slug);

        
        if (!postData) {
          setError('Post not found');
          setLoading(false);
          return;
        }
        
        setPost(postData);
        
        // Load markdown content
        const markdownContent = await getMarkdownContent(postData.filename);
        setContent(markdownContent);
        
        setLoading(false);
      } catch (error) {
        console.error('Error loading post:', error);
        setError('Error loading post');
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

  if (error || !post) {
    return (
      <div className="post-page">
        <div className="container">
          <div className="error">
            <h1>Post Not Found</h1>
            <p>{error || 'The requested post could not be found.'}</p>
            <Link to="/blog" className="btn">
              Back to Blog
            </Link>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="post-page">
      <div className="container">
        <article className="post-content">
          <header className="post-header">
            <nav className="post-nav">
              <Link to="/blog" className="back-link">
                ← Back to Blog
              </Link>
            </nav>
            
            <h1 className="post-title">{post.title}</h1>
            
            <div className="post-meta">
              <time className="post-date">
                {format(new Date(post.date), 'MMMM dd, yyyy')}
              </time>
              
              <div className="post-tags">
                {post.tags.map((tag, index) => (
                  <span key={index} className="tag">
                    #{tag}
                  </span>
                ))}
              </div>
            </div>
            
            <p className="post-description">{post.description}</p>
          </header>
          
          <div className="post-body">
            <ReactMarkdown>{content}</ReactMarkdown>
          </div>
          
          <footer className="post-footer">
            <div className="post-navigation">
              <Link to="/blog" className="btn">
                ← Back to Blog
              </Link>
            </div>
          </footer>
        </article>
      </div>
    </div>
  );
};

export default Post; 