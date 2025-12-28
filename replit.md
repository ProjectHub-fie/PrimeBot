# Portfolio Web Application

## Overview

This is a modern full-stack portfolio web application built with React and Node.js. The frontend features a responsive, single-page portfolio showcasing projects, skills, about information, and contact details with smooth scrolling navigation. The backend provides a REST API foundation with user management capabilities and uses PostgreSQL for data persistence through Drizzle ORM.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Frontend Architecture
- **Framework**: React 18 with TypeScript using Vite as the build tool
- **Styling**: Tailwind CSS with custom CSS variables for theming
- **UI Components**: Radix UI primitives with shadcn/ui component library for consistent design
- **State Management**: TanStack Query (React Query) for server state management
- **Routing**: Wouter for lightweight client-side routing
- **Theme System**: Custom theme provider supporting light/dark modes with system preference detection

### Backend Architecture
- **Runtime**: Node.js with Express.js framework
- **Language**: TypeScript with ES modules
- **API Design**: RESTful API structure with route registration system
- **Development**: Hot reload with Vite middleware integration in development mode
- **Error Handling**: Centralized error handling middleware with proper HTTP status codes

### Data Storage
- **Database**: PostgreSQL with connection pooling
- **ORM**: Drizzle ORM for type-safe database operations
- **Migration**: Drizzle Kit for schema migrations
- **Session Storage**: PostgreSQL-backed session storage with connect-pg-simple
- **Development Storage**: In-memory storage implementation for development/testing

### Authentication & Session Management
- **Session Management**: Express sessions with PostgreSQL storage
- **User Schema**: Basic user model with username/password authentication
- **Validation**: Zod schemas for runtime type validation and form validation

### Build & Deployment
- **Development**: Separate client and server processes with hot reload
- **Production Build**: Client assets built with Vite, server bundled with esbuild
- **Asset Serving**: Static file serving with development/production mode handling
- **Environment**: Environment-based configuration with proper NODE_ENV handling

## External Dependencies

### Core Dependencies
- **@neondatabase/serverless**: Neon PostgreSQL serverless driver for database connectivity
- **drizzle-orm & drizzle-zod**: Type-safe ORM with Zod integration for schema validation
- **@tanstack/react-query**: Server state management and caching
- **wouter**: Lightweight routing library for React

### UI & Styling
- **@radix-ui/***: Comprehensive set of unstyled, accessible UI primitives
- **tailwindcss**: Utility-first CSS framework with custom configuration
- **class-variance-authority**: Utility for creating variant-based component APIs
- **lucide-react**: Icon library for consistent iconography

### Development Tools
- **vite**: Fast build tool with hot module replacement
- **tsx**: TypeScript execution environment for development
- **esbuild**: Fast JavaScript bundler for production builds
- **@replit/vite-plugin-runtime-error-modal**: Replit-specific development error handling

### Form & Validation
- **react-hook-form**: Performant forms with minimal re-renders
- **@hookform/resolvers**: Validation resolver for various schema libraries
- **zod**: TypeScript-first schema validation library

### Utilities
- **date-fns**: Modern JavaScript date utility library
- **clsx & tailwind-merge**: Utility functions for conditional CSS classes
- **nanoid**: URL-safe unique string ID generator