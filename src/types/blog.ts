export interface BlogPost {
  slug: string;
  title: string;
  description: string;
  date: string;
  tags: string[];
  filename: string;
  thumbnail?: string;
  content?: string;
}

export interface BlogPostMeta {
  title: string;
  date: string;
  tags: string[];
} 