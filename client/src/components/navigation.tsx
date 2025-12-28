import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Sheet, SheetContent, SheetTrigger } from "@/components/ui/sheet";
import { Sun, Moon, Menu, X } from "lucide-react";
import { useTheme } from "./theme-provider";

export default function Navigation() {
  const [isOpen, setIsOpen] = useState(false);
  const { theme, setTheme } = useTheme();

  const handleScroll = (sectionId: string) => {
    const element = document.getElementById(sectionId);
    if (element) {
      element.scrollIntoView({ behavior: "smooth", block: "start" });
      setIsOpen(false);
    }
  };

  const NavLink = ({ href, children }: { href: string; children: React.ReactNode }) => (
    <button
      onClick={() => handleScroll(href)}
      className="text-slate-300 hover:text-blue-400 transition-colors duration-200"
      data-testid={`nav-link-${href}`}
    >
      {children}
    </button>
  );

  return (
    <nav className="fixed top-0 left-0 right-0 z-50 bg-slate-900/90 backdrop-blur-sm border-b border-slate-800">
      <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between items-center py-4">
          {/* Logo */}
          <button
            onClick={() => handleScroll("home")}
            className="text-xl font-bold text-blue-400"
            data-testid="nav-logo"
          >
            <span className="font-mono">&lt;</span>ProjectHub<span className="font-mono">/&gt;</span>
          </button>

          {/* Desktop Navigation */}
          <div className="hidden md:flex space-x-8">
            <NavLink href="home">Home</NavLink>
            <NavLink href="/request-project">Projects</NavLink>
            <Button
              className="bg-gradient-to-r from-emerald-500 to-teal-500 text-white hover:from-emerald-600 hover:to-teal-600 mr-3"
              onClick={() => window.location.href = "/request-project"}
            >
              Request Project
            </Button>
            <NavLink href="skills">Skills</NavLink>
            <NavLink href="about">About</NavLink>
            <NavLink href="contact">Contact</NavLink>
          </div>

          <div className="flex items-center space-x-4">
            {/* Theme Toggle */}
            <Button
              variant="outline"
              size="icon"
              onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
              className="hidden md:flex bg-slate-800 hover:bg-slate-700 border-slate-700"
              data-testid="theme-toggle"
            >
              {theme === "dark" ? (
                <Sun className="h-4 w-4 text-yellow-400" />
              ) : (
                <Moon className="h-4 w-4 text-blue-400" />
              )}
            </Button>

            {/* Mobile Menu */}
            <Sheet open={isOpen} onOpenChange={setIsOpen}>
              <SheetTrigger asChild>
                <Button
                  variant="outline"
                  size="icon"
                  className="md:hidden bg-slate-800 hover:bg-slate-700 border-slate-700"
                  data-testid="mobile-menu-trigger"
                >
                  <Menu className="h-4 w-4 text-slate-300" />
                </Button>
              </SheetTrigger>
              <SheetContent side="right" className="bg-slate-800 border-slate-700">
                <div className="flex flex-col space-y-6 mt-8">
                  <NavLink href="home">Home</NavLink>
                  <NavLink href="projects">Projects</NavLink>
                  <button
                    onClick={() => {
                      window.location.href = "/request-project";
                      setIsOpen(false);
                    }}
                    className="text-slate-300 hover:text-blue-400 transition-colors duration-200 text-left"
                    data-testid="mobile-nav-link-request-project"
                  >
                    Request Project
                  </button>
                  <NavLink href="skills">Skills</NavLink>
                  <NavLink href="about">About</NavLink>
                  <NavLink href="contact">Contact</NavLink>
                  <div className="px-3 py-2 space-y-2">
                  <Button
                    variant="ghost"
                    onClick={() => setTheme(theme === "dark" ? "light" : theme === "light" ? "system" : "dark")}
                    className="bg-slate-700 hover:bg-slate-600 border-slate-600 justify-start w-full"
                    data-testid="mobile-theme-toggle"
                  >
                    {theme === "dark" ? (
                      <>
                        <Sun className="h-4 w-4 text-yellow-400 mr-2" />
                        Switch to Light
                      </>
                    ) : theme === "light" ? (
                      <>
                        <Moon className="h-4 w-4 text-slate-400 mr-2" />
                        Switch to System
                      </>
                    ) : (
                      <>
                        <Moon className="h-4 w-4 text-blue-400 mr-2" />
                        Switch to Dark
                      </>
                    )}
                  </Button>
                  <div className="text-xs text-slate-400 px-2">
                    Current: {theme === "system" ? "System" : theme === "dark" ? "Dark" : "Light"}
                  </div>
                </div>
                </div>
              </SheetContent>
            </Sheet>
          </div>
        </div>
      </div>
    </nav>
  );
}
