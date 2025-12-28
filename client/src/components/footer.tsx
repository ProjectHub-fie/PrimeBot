import { Github, Twitter, Facebook, ChevronUp } from "lucide-react";
import { FaDiscord } from "react-icons/fa";

export default function Footer() {
  const handleScrollToTop = () => {
    const element = document.getElementById("home");
    if (element) {
      element.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  };

  const handleScroll = (sectionId: string) => {
    const element = document.getElementById(sectionId);
    if (element) {
      element.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  };

  const socialLinks = [
    { icon: <Github />, href: "https://github.com/rajroy1313/", name: "github" },
    { icon: <FaDiscord />, href: "https://discord.gg/gd7UNSfX86", name: "discord" },
    { icon: <Twitter />, href: "#", name: "twitter" },
    { icon: <Facebook />, href: "https://www.facebook.com/13yv13/", name: "facebook" }
  ];

  const navigationLinks = [
    { name: "Home", href: "home" },
    { name: "Projects", href: "projects" },
    { name: "Skills", href: "skills" },
    { name: "About", href: "about" },
    { name: "Contact", href: "contact" }
  ];

  return (
    <footer className="bg-slate-950 border-t border-slate-800 py-12">
      <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-8 mb-8">
          
          {/* Logo and Description */}
          <div className="md:col-span-1">
            <div className="text-xl font-bold text-blue-400 mb-4">
              <span className="font-mono">&lt;</span>ProjectHub<span className="font-mono">/&gt;</span>
            </div>
            <p className="text-slate-400 text-sm leading-relaxed">
              Full Stack Developer specializing in web applications, automation bots, and developer utilities. Building innovative solutions with modern technologies.
            </p>
          </div>

          {/* Navigation Links */}
          <div className="md:col-span-1">
            <h3 className="text-lg font-semibold text-slate-200 mb-4">Navigation</h3>
            <div className="space-y-2">
              {navigationLinks.map((link) => (
                <button
                  key={link.href}
                  onClick={() => handleScroll(link.href)}
                  className="block text-slate-400 hover:text-blue-400 transition-colors duration-200 text-left"
                  data-testid={`footer-nav-${link.href}`}
                >
                  {link.name}
                </button>
              ))}
            </div>
          </div>

          {/* Social Links */}
          <div className="md:col-span-1">
            <h3 className="text-lg font-semibold text-slate-200 mb-4">Connect</h3>
            <div className="flex space-x-4 mb-4">
              {socialLinks.map((link) => (
                <a
                  key={link.name}
                  href={link.href}
                  className="text-slate-400 hover:text-blue-400 transition-colors duration-200 text-xl"
                  data-testid={`footer-social-${link.name}`}
                >
                  {link.icon}
                </a>
              ))}
            </div>
          </div>

        </div>

        {/* Divider */}
        <div className="border-t border-slate-800 pt-8">
          <div className="flex flex-col md:flex-row justify-between items-center">
            
            {/* Copyright */}
            <p className="text-slate-400 text-sm mb-4 md:mb-0">
              © 2024 ProjectHub. All rights reserved.
            </p>

            {/* Back to Top Button */}
            <button
              onClick={handleScrollToTop}
              className="inline-flex items-center text-slate-400 hover:text-blue-400 transition-colors duration-200"
              data-testid="button-back-to-top"
            >
              <ChevronUp className="w-4 h-4 mr-2" />
              Back to Top
            </button>
          </div>
        </div>
      </div>
    </footer>
  );
}
