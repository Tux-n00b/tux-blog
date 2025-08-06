import React from 'react';
import { Link } from 'react-router-dom';
import { format } from 'date-fns';
import { BlogPost } from '../types/blog';
import './PostCard.css';

interface PostCardProps {
  post: BlogPost;
}

const PostCard: React.FC<PostCardProps> = ({ post }) => {
const thumbnailSrc = post.thumbnail?.startsWith('/')
  ? `${process.env.PUBLIC_URL}${post.thumbnail}`
  : `${process.env.PUBLIC_URL}/thumbnails/${post.thumbnail}`;


  return (
    <article className="post-card">
  <div className="post-thumbnail">
    <img 
      src={thumbnailSrc} 
      alt={post.title}
      onError={(e) => {
        e.currentTarget.style.display = 'none';
      }}
    />
  </div>
      
      <div className="post-card-header">
        <h3 className="post-title">
          <Link to={`/blog/${post.slug}`}>{post.title}</Link>
        </h3>
        <time className="post-date">
          {format(new Date(post.date), 'MMM dd, yyyy')}
        </time>
      </div>
      
      <p className="post-description">{post.description}</p>
      
      <div className="post-tags">
        {post.tags.map((tag, index) => (
          <span key={index} className="tag">
            #{tag}
          </span>
        ))}
      </div>
      
      <Link to={`/blog/${post.slug}`} className="read-more">
        READ MORE →
      </Link>
    </article>
  );
};

export default PostCard; 