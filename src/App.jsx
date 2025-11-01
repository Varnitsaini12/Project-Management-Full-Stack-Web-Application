import React, {
  useState,
  createContext,
  useContext,
  useMemo,
  useEffect,
  useRef,
  useCallback,
} from "react";
// NEW: Added Moon and Sun icons
import {
  Briefcase,
  Users,
  Database,
  AlertCircle,
  User,
  LogIn,
  LogOut,
  Edit,
  Trash2,
  Plus,
  Server,
  Zap,
  UserCheck,
  UserPlus,
  ShieldAlert,
  Moon,
  Sun,
} from "lucide-react";
import { v4 as uuidv4 } from "uuid";
import axios from "axios";

// --- CONFIG ---
// Make sure to replace this with your REAL Sitekey from hCaptcha
const HCAPTCHA_SITE_KEY = "420095e8-b2a2-4efe-89fc-45c452e0802c";

// --- API SERVICE ---
// This object will manage all our fetch calls
const apiService = {
  login: async (email, password, loginType, captchaToken) => {
    const response = await fetch("/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password, loginType, captchaToken }),
    });
    if (!response.ok) throw new Error(await response.text());
    return response.json();
  },

  getProjects: async (token) => {
    const response = await fetch("/api/projects", {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!response.ok) throw new Error(await response.text());
    return response.json();
  },

  getUsers: async (token) => {
    const response = await fetch("/api/users", {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!response.ok) throw new Error(await response.text());
    return response.json();
  },

  createProject: async (project, token) => {
    const response = await fetch("/api/projects", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(project),
    });
    if (!response.ok) throw new Error(await response.text());
    return response.json();
  },

  updateProject: async (project, token) => {
    const response = await fetch(`/api/projects/${project.id}`, {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(project),
    });
    if (!response.ok) throw new Error(await response.text());
    return response.json();
  },

  deleteProject: async (projectId, token) => {
    const response = await fetch(`/api/projects/${projectId}`, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!response.ok) throw new Error(await response.text());
    return response.json();
  },

  createUser: async (userData, token, captchaToken) => {
    const response = await fetch("/api/users", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ ...userData, captchaToken }),
    });
    if (!response.ok) throw new Error(await response.text());
    return response.json();
  },
};
// --- END API SERVICE ---

// --- ROUTER CONTEXT & HOOK ---
const RouterContext = createContext();

const useSimpleRouter = () => {
  const [route, setRoute] = useState(window.location.pathname);

  useEffect(() => {
    const onPopState = () => {
      setRoute(window.location.pathname);
    };
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, []);

  const navigate = (path) => {
    window.history.pushState({}, "", path);
    setRoute(path);
  };

  return { route, navigate };
};

const useRouter = () => useContext(RouterContext);
// --- END ROUTER ---

// --- AUTHENTICATION CONTEXT ---
const AuthContext = createContext();

function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(() => localStorage.getItem("token"));
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const [isDarkMode, setIsDarkMode] = useState(() => {
    const savedTheme = localStorage.getItem("theme");
    if (savedTheme) {
      return savedTheme === "dark";
    }
    return (
      window.matchMedia &&
      window.matchMedia("(prefers-color-scheme: dark)").matches
    );
  });

  useEffect(() => {
    const root = window.document.documentElement;
    if (isDarkMode) {
      root.classList.add("dark");
      localStorage.setItem("theme", "dark");
    } else {
      root.classList.remove("dark");
      localStorage.setItem("theme", "light");
    }
  }, [isDarkMode]);

  const toggleDarkMode = () => {
    setIsDarkMode((prevMode) => !prevMode);
  };

  useEffect(() => {
    if (token) {
      try {
        const payload = JSON.parse(atob(token.split(".")[1]));
        setUser(payload);
      } catch (e) {
        console.error("Invalid token, logging out.");
        logout();
      }
    }
  }, [token]);

  const login = async (email, password, loginType, captchaToken) => {
    setLoading(true);
    // setError(null); // <-- This is now done in handleSubmit
    try {
      const { user, token } = await apiService.login(
        email,
        password,
        loginType,
        captchaToken
      );
      setUser(user);
      setToken(token);
      localStorage.setItem("token", token);
    } catch (err) {
      setError(err.message);
      throw err; // Re-throw to be caught by handleSubmit
    } finally {
      setLoading(false);
    }
  };

  const logout = () => {
    setUser(null);
    setToken(null);
    localStorage.removeItem("token");
  };

  // NEW: Function to clear the error state
  const clearError = () => setError(null);

  const authValue = useMemo(
    () => ({
      user,
      token,
      loading,
      error,
      login,
      logout,
      clearError, // <-- Pass down clearError
      isDarkMode,
      toggleDarkMode,
    }),
    [user, token, loading, error, isDarkMode]
  );

  return (
    <AuthContext.Provider value={authValue}>{children}</AuthContext.Provider>
  );
}

function useAuth() {
  return useContext(AuthContext);
}
// --- END AUTHENTICATION CONTEXT ---

// --- hCAPTCHA COMPONENT ---
/**
 * A manual hCaptcha component that loads the script.
 * @param {{
 * onVerify: (token: string) => void,
 * onExpire: () => void,
 * onError: (error: string) => void,
 * onLoad: (reset: () => void) => void
 * }} props
 */
function ManualHCaptcha({ onVerify, onExpire, onError, onLoad }) {
  const captchaRef = useRef(null);
  const widgetIdRef = useRef(null);

  const loadScript = useCallback(() => {
    if (window.hcaptcha) {
      renderCaptcha();
      return;
    }

    const script = document.createElement("script");
    script.src = "https://js.hcaptcha.com/1/api.js?onload=onHCaptchaLoaded";
    script.async = true;
    script.defer = true;

    window.onHCaptchaLoaded = () => {
      console.log("hCaptcha script loaded.");
      renderCaptcha();
    };

    document.body.appendChild(script);
  }, []); // Empty dependency array, this function is stable

  // --- MODIFICATION: Wrapped resetCaptcha in useCallback ---
  const resetCaptcha = useCallback(() => {
    if (window.hcaptcha && widgetIdRef.current !== null) {
      try {
        window.hcaptcha.reset(widgetIdRef.current);
      } catch (e) {
        console.warn("hCaptcha reset error:", e);
      }
    }
  }, []); // widgetIdRef is a ref, so it's stable

  const renderCaptcha = () => {
    if (captchaRef.current && window.hcaptcha && widgetIdRef.current === null) {
      try {
        const id = window.hcaptcha.render(captchaRef.current, {
          sitekey: HCAPTCHA_SITE_KEY,
          callback: onVerify,
          // --- MODIFICATION: Pass only the callback ---
          "expired-callback": onExpire,
          "error-callback": onError,
        });
        widgetIdRef.current = id;
        // --- MODIFICATION: Pass the reset function to the parent via onLoad ---
        if (onLoad) {
          onLoad(resetCaptcha);
        }
      } catch (e) {
        console.error("Failed to render hCaptcha:", e);
      }
    }
  };

  // --- MODIFICATION: Removed incorrect useEffect ---

  useEffect(() => {
    loadScript();

    // Cleanup
    return () => {
      if (window.hcaptcha && widgetIdRef.current !== null) {
        try {
          // Check if the hcaptcha object and the widget still exist
          if (window.hcaptcha.remove) {
            window.hcaptcha.remove(widgetIdRef.current);
          }
        } catch (e) {
          // This can error if the component unmounts quickly, ignore
        }
        widgetIdRef.current = null;
      }
    };
  }, [loadScript]);

  return <div ref={captchaRef}></div>;
}

// --- ERROR BOUNDARY ---
class CaptchaErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true };
  }

  componentDidCatch(error, errorInfo) {
    console.error("hCaptcha Error Boundary caught:", error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="p-4 text-center text-red-700 bg-red-100 rounded-lg dark:bg-red-900 dark:text-red-200">
          <AlertCircle className="w-5 h-5 inline-block mr-2" />
          Could not load security captcha. Please check your connection and
          refresh.
        </div>
      );
    }
    return this.props.children;
  }
}
// --- END ERROR BOUNDARY ---

// --- MAIN APP COMPONENT ---
export default function App() {
  const { route, navigate } = useSimpleRouter();

  return (
    <AuthProvider>
      <RouterContext.Provider value={{ route, navigate }}>
        {/* Added dark mode class to root */}
        <div className="min-h-screen bg-gray-100 dark:bg-gray-900 font-inter">
          <Header />
          <main className="p-4 md:p-8">
            <PageContent />
          </main>
          <Footer />
        </div>
      </RouterContext.Provider>
    </AuthProvider>
  );
}
// --- END MAIN APP COMPONENT ---

// --- LAYOUT COMPONENTS ---
function Header() {
  const { user, logout, isDarkMode, toggleDarkMode } = useAuth(); // <-- Get dark mode state
  const { navigate } = useRouter();

  const goHome = (e) => {
    e.preventDefault();
    navigate("/");
  };

  return (
    // Added dark mode styles
    <header className="bg-white shadow-md dark:bg-gray-800 dark:border-b dark:border-gray-700">
      <nav className="container mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 flex justify-between items-center h-16">
        <a
          href="/"
          onClick={goHome}
          className="flex items-center space-x-2 cursor-pointer"
        >
          <Briefcase className="w-8 h-8 text-blue-600" />
          {/* Added dark mode styles */}
          <span className="text-2xl font-bold text-gray-800 dark:text-white">
            CTZ Manager
          </span>
        </a>

        {user && (
          <div className="flex items-center space-x-4">
            {/* Added dark mode styles */}
            <span className="text-gray-600 hidden sm:inline dark:text-gray-300">
              Welcome, <strong className="font-medium">{user.name}</strong> (
              {user.role})
            </span>

            {/* --- NEW DARK MODE TOGGLE BUTTON --- */}
            <Button
              onClick={toggleDarkMode}
              variant="icon"
              size="sm"
              className="text-gray-600 dark:text-gray-300 dark:hover:bg-gray-700"
              title={
                isDarkMode ? "Switch to Light Mode" : "Switch to Dark Mode"
              }
            >
              {isDarkMode ? (
                <Sun className="w-5 h-5" />
              ) : (
                <Moon className="w-5 h-5" />
              )}
            </Button>
            {/* --- END TOGGLE --- */}

            <Button onClick={logout} variant="secondary" size="sm">
              <LogOut className="w-4 h-4 mr-2" />
              Logout
            </Button>
          </div>
        )}
      </nav>
    </header>
  );
}

function Footer() {
  return (
    // Added dark mode styles
    <footer className="text-center p-4 mt-8 text-gray-500 dark:text-gray-400 text-sm">
      © {new Date().getFullYear()} CTZ Manager. All rights reserved.
    </footer>
  );
}

function PageContent() {
  const { user } = useAuth();
  const { route } = useRouter();

  if (route === "/supersu") {
    if (!user) {
      return <SuperUserLoginPage />;
    }
    if (user.role === "superuser") {
      return <SuperUserDashboard />;
    } else {
      return <NotAuthorizedPage />;
    }
  }

  if (!user) {
    return <LoginPage />;
  }

  switch (user.role) {
    case "employee":
      return <EmployeeDashboard />;
    case "manager":
      return <ManagerDashboard />;
    case "superuser":
      return <ManagerDashboard />;
    default:
      return <NotAuthorizedPage />;
  }
}

function NotAuthorizedPage() {
  const { navigate } = useRouter();
  return (
    <div className="container mx-auto max-w-lg mt-10">
      {/* Added dark mode styles */}
      <div className="flex flex-col items-center justify-center text-center p-10 bg-white dark:bg-gray-800 rounded-lg shadow-lg">
        <ShieldAlert className="w-16 h-16 text-red-500 mb-4" />
        <h1 className="text-3xl font-bold text-gray-800 dark:text-gray-100 mb-2">
          Access Denied
        </h1>
        <p className="text-lg text-gray-600 dark:text-gray-300 mb-6">
          You do not have permission to view this page.
        </p>
        <Button onClick={() => navigate("/")}>Go to Your Dashboard</Button>
      </div>
    </div>
  );
}
// --- END LAYOUT COMPONENTS ---

// --- LOGIN PAGES ---
function LoginPage() {
  // --- MODIFICATION: Get clearError from useAuth ---
  const { login, loading, error, clearError } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [captchaToken, setCaptchaToken] = useState(null);
  const [captchaError, setCaptchaError] = useState(false);
  const resetCaptchaRef = useRef(null);

  const handleSubmit = (e) => {
    e.preventDefault();

    // --- MODIFICATION: Clear all errors on submit ---
    clearError();
    setCaptchaError(false);

    if (!captchaToken) {
      setCaptchaError(true);
      return;
    }

    login(email, password, "main", captchaToken)
      .catch(() => {
        // Error is already set in AuthContext, just catch
      })
      .finally(() => {
        // Reset captcha after every attempt
        setCaptchaToken(null);
        resetCaptchaRef.current?.();
      });
  };

  return (
    <div className="flex flex-col items-center justify-center mt-16">
      {/* Added dark mode styles */}
      <div className="w-full max-w-md p-8 bg-white dark:bg-gray-800 rounded-lg shadow-lg">
        <div className="flex justify-center mb-6">
          <User className="w-16 h-16 text-blue-600" />
        </div>
        <h2 className="text-2xl font-bold text-center text-gray-800 dark:text-gray-100 mb-6">
          Login to CTZ Manager
        </h2>

        <form onSubmit={handleSubmit} className="space-y-4">
          <Input
            id="email"
            type="email"
            placeholder="Email (e.g., employee@ctz.com)"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
          />
          <Input
            id="password"
            type="password"
            placeholder="Password (e.g., password)"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />

          <CaptchaErrorBoundary>
            <div className="flex justify-center">
              <ManualHCaptcha
                onVerify={setCaptchaToken}
                // --- MODIFICATION: This is the fix ---
                onExpire={() => {
                  setCaptchaToken(null);
                  resetCaptchaRef.current?.();
                }}
                onError={(err) => {
                  console.error("Captcha error:", err);
                  setCaptchaError(true);
                }}
                // --- MODIFICATION: This prop wires up the reset function ---
                onLoad={(reset) => {
                  resetCaptchaRef.current = reset;
                }}
              />
            </div>
          </CaptchaErrorBoundary>

          {(error || captchaError) && (
            <div className="flex items-center p-3 text-sm text-red-700 bg-red-100 rounded-lg dark:bg-red-900 dark:text-red-200">
              <AlertCircle className="w-5 h-5 mr-2" />
              {/* --- MODIFICATION: Prioritize captcha error --- */}
              <span>
                {captchaError ? "Please complete the captcha." : error}
              </span>
            </div>
          )}

          <Button type="submit" disabled={loading} className="w-full">
            <LogIn className="w-4 h-4 mr-2" />
            {loading ? "Logging in..." : "Login"}
          </Button>
        </form>
      </div>
    </div>
  );
}

function SuperUserLoginPage() {
  // --- MODIFICATION: Get clearError from useAuth ---
  const { login, loading, error, clearError } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [captchaToken, setCaptchaToken] = useState(null);
  const [captchaError, setCaptchaError] = useState(false);
  const resetCaptchaRef = useRef(null);

  const handleSubmit = (e) => {
    e.preventDefault();

    // --- MODIFICATION: Clear all errors on submit ---
    clearError();
    setCaptchaError(false);

    if (!captchaToken) {
      setCaptchaError(true);
      return;
    }

    login(email, password, "superuser", captchaToken)
      .catch(() => {
        // Error is already set in AuthContext, just catch
      })
      .finally(() => {
        setCaptchaToken(null);
        resetCaptchaRef.current?.();
      });
  };

  return (
    <div className="flex flex-col items-center justify-center mt-16">
      {/* Added dark mode styles */}
      <div className="w-full max-w-md p-8 bg-white dark:bg-gray-800 rounded-lg shadow-lg border-2 border-red-500">
        <div className="flex justify-center mb-6">
          <ShieldAlert className="w-16 h-16 text-red-600" />
        </div>
        <h2 className="text-2xl font-bold text-center text-gray-800 dark:text-gray-100 mb-6">
          Welcome Super Admin
        </h2>

        <form onSubmit={handleSubmit} className="space-y-4">
          <Input
            id="email"
            type="email"
            placeholder="Email (e.g., super@ctz.com)"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
          />
          <Input
            id="password"
            type="password"
            placeholder="Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />

          <CaptchaErrorBoundary>
            <div className="flex justify-center">
              <ManualHCaptcha
                onVerify={setCaptchaToken}
                // --- MODIFICATION: This is the fix ---
                onExpire={() => {
                  setCaptchaToken(null);
                  resetCaptchaRef.current?.();
                }}
                onError={(err) => {
                  console.error("Captcha error:", err);
                  setCaptchaError(true);
                }}
                // --- MODIFICATION: This prop wires up the reset function ---
                onLoad={(reset) => {
                  resetCaptchaRef.current = reset;
                }}
              />
            </div>
          </CaptchaErrorBoundary>

          {(error || captchaError) && (
            <div className="flex items-center p-3 text-sm text-red-700 bg-red-100 rounded-lg dark:bg-red-900 dark:text-red-200">
              <AlertCircle className="w-5 h-5 mr-2" />
              {/* --- MODIFICATION: Prioritize captcha error --- */}
              <span>
                {captchaError ? "Please complete the captcha." : error}
              </span>
            </div>
          )}

          <Button
            type="submit"
            disabled={loading}
            className="w-full bg-red-600 hover:bg-red-700 focus:ring-red-500"
          >
            <LogIn className="w-4 h-4 mr-2" />
            {loading ? "Logging in..." : "Login"}
          </Button>
        </form>
      </div>
    </div>
  );
}
// --- END LOGIN PAGES ---

// --- DASHBOARDS ---
function EmployeeDashboard() {
  const { user, token } = useAuth();
  const [projects, setProjects] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    apiService
      .getProjects(token)
      .then((data) => {
        setProjects(data);
        setLoading(false);
      })
      .catch((err) => {
        console.error(err);
        setLoading(false);
      });
  }, [token]);

  return (
    <DashboardLayout
      title="Employee Dashboard"
      subtitle="Here are the projects assigned to you."
    >
      {loading ? (
        <p className="dark:text-gray-300">Loading projects...</p>
      ) : (
        <ProjectList
          projects={projects.filter((p) => p.assignedTo === user.id)}
        />
      )}
    </DashboardLayout>
  );
}

function ManagerDashboard() {
  const { user, token } = useAuth();
  const [projects, setProjects] = useState([]);
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [isProjectModalOpen, setIsProjectModalOpen] = useState(false);
  const [isUserModalOpen, setIsUserModalOpen] = useState(false); // <-- New state
  const [editingProject, setEditingProject] = useState(null);

  const fetchAllData = () => {
    setLoading(true);
    Promise.all([apiService.getProjects(token), apiService.getUsers(token)])
      .then(([projectData, userData]) => {
        setProjects(projectData);
        setUsers(userData.filter((u) => u.role === "employee"));
        setLoading(false);
      })
      .catch((err) => {
        console.error(err);
        setLoading(false);
      });
  };

  useEffect(() => {
    fetchAllData();
  }, [token]);

  const openCreateProjectModal = () => {
    setEditingProject(null);
    setIsProjectModalOpen(true);
  };

  const openEditProjectModal = (project) => {
    setEditingProject(project);
    setIsProjectModalOpen(true);
  };

  const [showConfirm, setShowConfirm] = useState(false);
  const [projectIdToDelete, setProjectIdToDelete] = useState(null);

  const handleDeleteClick = (projectId) => {
    setProjectIdToDelete(projectId);
    setShowConfirm(true);
  };

  const confirmDelete = async () => {
    if (projectIdToDelete) {
      await apiService.deleteProject(projectIdToDelete, token);
      fetchAllData();
    }
    setShowConfirm(false);
    setProjectIdToDelete(null);
  };

  const handleSaveProject = async (project) => {
    if (editingProject) {
      await apiService.updateProject(project, token);
    } else {
      await apiService.createProject(project, token);
    }
    fetchAllData();
    setIsProjectModalOpen(false);
    setEditingProject(null);
  };

  const handleSaveUser = async (userData, captchaToken) => {
    try {
      await apiService.createUser(userData, token, captchaToken);
      // No need to refresh user list here, managers don't see it
      setIsUserModalOpen(false);
    } catch (error) {
      console.error("Failed to create user:", error);
      // The modal will show its own error
      throw error;
    }
  };

  return (
    <DashboardLayout
      title="Manager Dashboard"
      subtitle="Assign and manage all projects."
    >
      <div className="mb-6 flex justify-end space-x-3">
        {/* NEW "Add User" Button */}
        <Button onClick={() => setIsUserModalOpen(true)} variant="secondary">
          <UserPlus className="w-4 h-4 mr-2" />
          Add Employee
        </Button>
        <Button onClick={openCreateProjectModal}>
          <Plus className="w-4 h-4 mr-2" />
          Add New Project
        </Button>
      </div>

      {loading ? (
        <p className="dark:text-gray-300">Loading projects...</p>
      ) : (
        <ProjectList
          projects={projects}
          users={users}
          onEdit={openEditProjectModal}
          onDelete={handleDeleteClick}
          isManager={true}
        />
      )}

      {isProjectModalOpen && (
        <ProjectModal
          project={editingProject}
          employees={users}
          onClose={() => setIsProjectModalOpen(false)}
          onSave={handleSaveProject}
        />
      )}

      {/* NEW User Form Modal */}
      {isUserModalOpen && (
        <UserFormModal
          onClose={() => setIsUserModalOpen(false)}
          onSave={handleSaveUser}
          allowedRoles={["employee"]} // Managers can only create employees
        />
      )}

      {showConfirm && (
        <ConfirmationModal
          title="Delete Project"
          message="Are you sure you want to delete this project? This action cannot be undone."
          onConfirm={confirmDelete}
          onCancel={() => setShowConfirm(false)}
        />
      )}
    </DashboardLayout>
  );
}

function SuperUserDashboard() {
  const { token } = useAuth();
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [isUserModalOpen, setIsUserModalOpen] = useState(false); // <-- New state

  const fetchAllUsers = () => {
    setLoading(true);
    apiService
      .getUsers(token)
      .then((data) => {
        setUsers(data);
        setLoading(false);
      })
      .catch((err) => {
        console.error(err);
        setLoading(false);
      });
  };

  useEffect(() => {
    fetchAllUsers();
  }, [token]);

  const handleSaveUser = async (userData, captchaToken) => {
    try {
      await apiService.createUser(userData, token, captchaToken);
      fetchAllUsers(); // <-- Refresh the user list!
      setIsUserModalOpen(false);
    } catch (error) {
      console.error("Failed to create user:", error);
      throw error;
    }
  };

  return (
    <DashboardLayout
      title="Super User Dashboard"
      subtitle="Manage system, database, and n8n workflows."
    >
      {/* System Status Widgets */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
        <DashboardCard>
          <DashboardCard.Header>
            <Server className="text-blue-500" />
            <DashboardCard.Title>MySQL Database</DashboardCard.Title>
          </DashboardCard.Header>
          <DashboardCard.Content>
            <p className="text-2xl font-semibold text-gray-800 dark:text-gray-100">
              Online
            </p>
            <p className="text-sm text-green-600">Status: OK</p>
          </DashboardCard.Content>
        </DashboardCard>

        <DashboardCard>
          <DashboardCard.Header>
            <Zap className="text-orange-500" />
            <DashboardCard.Title>n8n Server</DashboardCard.Title>
          </DashboardCard.Header>
          <DashboardCard.Content>
            <p className="text-2xl font-semibold text-gray-800 dark:text-gray-100">
              3 Workflows
            </p>
            <p className="text-sm text-green-600">All Active</p>
          </DashboardCard.Content>
        </DashboardCard>

        <DashboardCard>
          <DashboardCard.Header>
            <UserCheck className="text-green-500" />
            <DashboardCard.Title>Authentication</DashboardCard.Title>
          </DashboardCard.Header>
          <DashboardCard.Content>
            <p className="text-2xl font-semibold text-gray-800 dark:text-gray-100">
              JWT Enabled
            </p>
            <p className="text-sm text-gray-500 dark:text-gray-400">Secure</p>
          </DashboardCard.Content>
        </DashboardCard>
      </div>

      {/* User Management Table */}
      <DashboardCard>
        <DashboardCard.Header>
          <Users className="text-indigo-500" />
          <DashboardCard.Title>User Management</DashboardCard.Title>
          {/* Updated "Add User" Button */}
          <Button
            onClick={() => setIsUserModalOpen(true)}
            variant="secondary"
            size="sm"
            className="ml-auto"
          >
            <UserPlus className="w-4 h-4 mr-2" />
            Add User
          </Button>
        </DashboardCard.Header>
        <DashboardCard.Content>
          {loading ? (
            <p className="dark:text-gray-300">Loading users...</p>
          ) : (
            <UserTable users={users} />
          )}
        </DashboardCard.Content>
      </DashboardCard>

      {/* NEW User Form Modal */}
      {isUserModalOpen && (
        <UserFormModal
          onClose={() => setIsUserModalOpen(false)}
          onSave={handleSaveUser}
          allowedRoles={["employee", "manager", "superuser"]} // Super Users can create any role
        />
      )}
    </DashboardLayout>
  );
}

function DashboardLayout({ title, subtitle, children }) {
  return (
    <div className="container mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
      {/* Added dark mode styles */}
      <h1 className="text-3xl font-bold text-gray-900 dark:text-gray-100 mb-2">
        {title}
      </h1>
      <p className="text-lg text-gray-600 dark:text-gray-300 mb-8">
        {subtitle}
      </p>
      <div className="bg-white rounded-lg shadow-lg p-6 min-h-[400px] dark:bg-gray-800">
        {children}
      </div>
    </div>
  );
}
// --- END DASHBOARDS ---

// --- REUSABLE COMPONENTS ---
function ProjectList({ projects, users, onEdit, onDelete, isManager = false }) {
  const userMap = useMemo(() => {
    if (!users) return {};
    return users.reduce((acc, user) => {
      acc[user.id] = user.name;
      return acc;
    }, {});
  }, [users]);

  if (projects.length === 0) {
    return (
      <p className="text-gray-500 dark:text-gray-400">No projects found.</p>
    );
  }

  return (
    <div className="overflow-x-auto">
      {/* Added dark mode styles */}
      <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
        <thead className="bg-gray-50 dark:bg-gray-700">
          <tr>
            <Th>Project Name</Th>
            <Th>Status</Th>
            <Th>Assigned To</Th>
            {isManager && <Th>Actions</Th>}
          </tr>
        </thead>
        <tbody className="bg-white divide-y divide-gray-200 dark:bg-gray-800 dark:divide-gray-700">
          {projects.map((project) => (
            <tr key={project.id}>
              <Td>{project.name}</Td>
              <Td>
                <StatusBadge status={project.status} />
              </Td>
              <Td>
                {isManager
                  ? userMap[project.assignedTo] || (
                      <span className="text-gray-400 dark:text-gray-500">
                        Unassigned
                      </span>
                    )
                  : "Me"}
              </Td>
              {isManager && (
                <Td className="space-x-2">
                  <Button
                    variant="icon"
                    size="sm"
                    onClick={() => onEdit(project)}
                  >
                    <Edit className="w-4 h-4" />
                  </Button>
                  <Button
                    variant="icon-danger"
                    size="sm"
                    onClick={() => onDelete(project.id)}
                  >
                    <Trash2 className="w-4 h-4" />
                  </Button>
                </Td>
              )}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function UserTable({ users }) {
  return (
    <div className="overflow-x-auto">
      {/* Added dark mode styles */}
      <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
        <thead className="bg-gray-50 dark:bg-gray-700">
          <tr>
            <Th>Name</Th>
            <Th>Email</Th>
            <Th>Role</Th>
            <Th>Actions</Th>
          </tr>
        </thead>
        <tbody className="bg-white divide-y divide-gray-200 dark:bg-gray-800 dark:divide-gray-700">
          {users.map((user) => (
            <tr key={user.id}>
              <Td>{user.name}</Td>
              <Td>{user.email}</Td>
              <Td>
                <span
                  className={`px-2 py-1 inline-flex text-xs leading-5 font-semibold rounded-full ${
                    user.role === "superuser"
                      ? "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200"
                      : user.role === "manager"
                      ? "bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200"
                      : "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200"
                  }`}
                >
                  {user.role}
                </span>
              </Td>
              <Td className="space-x-2">
                <Button variant="icon" size="sm">
                  <Edit className="w-4 h-4" />
                </Button>
                <Button variant="icon-danger" size="sm">
                  <Trash2 className="w-4 h-4" />
                </Button>
              </Td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function ProjectModal({ project, employees, onClose, onSave }) {
  const [name, setName] = useState(project ? project.name : "");
  const [status, setStatus] = useState(project ? project.status : "Planning");
  const [assignedTo, setAssignedTo] = useState(
    project ? project.assignedTo : ""
  );

  const handleSubmit = (e) => {
    e.preventDefault();
    onSave({
      id: project ? project.id : null,
      name,
      status,
      assignedTo: assignedTo ? assignedTo : null,
    });
  };

  return (
    // Added dark mode styles
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow-2xl p-6 w-full max-w-lg">
        <h3 className="text-xl font-medium text-gray-900 dark:text-gray-100 mb-4">
          {project ? "Edit Project" : "Create New Project"}
        </h3>
        <form onSubmit={handleSubmit} className="space-y-4">
          <Input
            id="projectName"
            label="Project Name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            required
          />
          <Select
            id="projectStatus"
            label="Status"
            value={status}
            onChange={(e) => setStatus(e.target.value)}
          >
            <option>Planning</option>
            <option>In Progress</option>
            <option>Completed</option>
            <option>On Hold</option>
          </Select>
          <Select
            id="projectAssignment"
            label="Assign To"
            value={assignedTo}
            onChange={(e) => setAssignedTo(e.target.value)}
          >
            <option value="">Unassigned</option>
            {employees.map((emp) => (
              <option key={emp.id} value={emp.id}>
                {emp.name}
              </option>
            ))}
          </Select>

          <div className="flex justify-end space-x-3 pt-4">
            <Button type="button" variant="secondary" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit">
              {project ? "Save Changes" : "Create Project"}
            </Button>
          </div>
        </form>
      </div>
    </div>
  );
}

// NEW: User Creation Modal
function UserFormModal({ onClose, onSave, allowedRoles }) {
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  // Set default role to the first one allowed
  const [role, setRole] = useState(allowedRoles[0] || "employee");

  const [captchaToken, setCaptchaToken] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);
  const resetCaptchaRef = useRef(null);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null); // Clear error on new submit
    if (!captchaToken) {
      setError("Please complete the captcha.");
      return;
    }
    setLoading(true);

    try {
      await onSave({ name, email, password, role }, captchaToken);
      onClose(); // Close modal on success
    } catch (err) {
      setError(err.message || "Failed to create user.");
      // Reset captcha on failure
      setCaptchaToken(null);
      resetCaptchaRef.current?.();
    } finally {
      setLoading(false);
    }
  };

  return (
    // Added dark mode styles
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow-2xl p-6 w-full max-w-lg">
        <h3 className="text-xl font-medium text-gray-900 dark:text-gray-100 mb-4">
          Create New User
        </h3>
        <form onSubmit={handleSubmit} className="space-y-4">
          <Input
            id="userName"
            label="Full Name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            required
          />
          <Input
            id="userEmail"
            label="Email"
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
          />
          <Input
            id="userPassword"
            label="Password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />
          <Select
            id="userRole"
            label="Role"
            value={role}
            onChange={(e) => setRole(e.target.value)}
          >
            {allowedRoles.map((r) => (
              <option key={r} value={r} className="capitalize">
                {r}
              </option>
            ))}
          </Select>

          <CaptchaErrorBoundary>
            <div className="flex justify-center">
              <ManualHCaptcha
                onVerify={setCaptchaToken}
                // --- MODIFICATION: This is the fix ---
                onExpire={() => {
                  setCaptchaToken(null);
                  resetCaptchaRef.current?.();
                }}
                onError={(err) => {
                  console.error("Captcha error:", err);
                  setError("Captcha failed to load.");
                }}
                // --- MODIFICATION: This prop wires up the reset function ---
                onLoad={(reset) => {
                  resetCaptchaRef.current = reset;
                }}
              />
            </div>
          </CaptchaErrorBoundary>

          {error && (
            <div className="flex items-center p-3 text-sm text-red-700 bg-red-100 rounded-lg dark:bg-red-900 dark:text-red-200">
              <AlertCircle className="w-5 h-5 mr-2" />
              <span>{error}</span>
            </div>
          )}

          <div className="flex justify-end space-x-3 pt-4">
            <Button
              type="button"
              variant="secondary"
              onClick={onClose}
              disabled={loading}
            >
              Cancel
            </Button>
            <Button type="submit" disabled={loading}>
              {loading ? "Creating User..." : "Create User"}
            </Button>
          </div>
        </form>
      </div>
    </div>
  );
}

function ConfirmationModal({ title, message, onConfirm, onCancel }) {
  return (
    // Added dark mode styles
    <div className="fixed inset-0 bg-black bg-opacity-60 flex items-center justify-center z-50 p-4">
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow-2xl p-6 w-full max-w-sm">
        <div className="flex items-start">
          <div className="flex-shrink-0 flex items-center justify-center h-12 w-12 rounded-full bg-red-100 sm:mx-0 sm:h-10 sm:w-10">
            <AlertCircle className="h-6 w-6 text-red-600" />
          </div>
          <div className="ml-4 text-left">
            <h3 className="text-lg font-medium text-gray-900 dark:text-gray-100">
              {title}
            </h3>
            <div className="mt-2">
              <p className="text-sm text-gray-500 dark:text-gray-400">
                {message}
              </p>
            </div>
          </div>
        </div>
        <div className="mt-5 sm:mt-4 sm:flex sm:flex-row-reverse">
          <Button
            type="button"
            variant="primary"
            className="bg-red-600 hover:bg-red-700 focus:ring-red-500 w-full sm:w-auto sm:ml-3"
            onClick={onConfirm}
          >
            Confirm
          </Button>
          <Button
            type="button"
            variant="secondary"
            className="mt-3 w-full sm:w-auto sm:mt-0"
            onClick={onCancel}
          >
            Cancel
          </Button>
        </div>
      </div>
    </div>
  );
}

// Added dark mode styles
function DashboardCard({ children }) {
  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-5">
      {children}
    </div>
  );
}
DashboardCard.Header = ({ children }) => (
  <div className="flex items-center space-x-3 mb-4 pb-4 border-b border-gray-200 dark:border-gray-700">
    {children}
  </div>
);
DashboardCard.Title = ({ children }) => (
  <h3 className="text-lg font-medium text-gray-700 dark:text-gray-200">
    {children}
  </h3>
);
DashboardCard.Content = ({ children }) => (
  <div className="text-gray-600 dark:text-gray-300">{children}</div>
);

// Added dark mode styles
function Input({ id, label, ...props }) {
  return (
    <div>
      {label && (
        <label
          htmlFor={id}
          className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1"
        >
          {label}
        </label>
      )}
      <input
        id={id}
        {...props}
        className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:border-gray-600 dark:text-white dark:placeholder-gray-400"
      />
    </div>
  );
}

// Added dark mode styles
function Select({ id, label, children, ...props }) {
  return (
    <div>
      {label && (
        <label
          htmlFor={id}
          className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1"
        >
          {label}
        </label>
      )}
      <select
        id={id}
        {...props}
        className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:border-gray-600 dark:text-white"
      >
        {children}
      </select>
    </div>
  );
}

// Added dark mode styles
function Button({
  children,
  onClick,
  type = "button",
  variant = "primary",
  size = "md",
  disabled = false,
  className = "",
}) {
  const baseStyle =
    "inline-flex items-center justify-center font-medium rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-offset-2 dark:focus:ring-offset-gray-800 transition-all duration-150";

  const variants = {
    primary:
      "bg-blue-600 text-white hover:bg-blue-700 focus:ring-blue-500 disabled:bg-blue-300",
    secondary:
      "bg-gray-200 text-gray-800 hover:bg-gray-300 focus:ring-gray-400 disabled:bg-gray-100 dark:bg-gray-700 dark:text-gray-200 dark:hover:bg-gray-600 dark:focus:ring-gray-500",
    outline:
      "bg-white text-gray-700 border border-gray-300 hover:bg-gray-50 focus:ring-blue-500 disabled:bg-gray-50 dark:bg-gray-800 dark:text-gray-200 dark:border-gray-600 dark:hover:bg-gray-700",
    icon: "text-gray-500 hover:text-gray-800 hover:bg-gray-100 focus:ring-gray-400 rounded-full dark:text-gray-400 dark:hover:text-white dark:hover:bg-gray-700",
    "icon-danger":
      "text-red-500 hover:text-red-700 hover:bg-red-50 focus:ring-red-400 rounded-full dark:text-red-400 dark:hover:text-red-300 dark:hover:bg-red-900",
  };

  const sizes = {
    sm: "px-3 py-1.5 text-sm",
    md: "px-4 py-2 text-base",
    lg: "px-6 py-3 text-lg",
  };

  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled}
      className={`${baseStyle} ${variants[variant]} ${sizes[size]} ${className}`}
    >
      {children}
    </button>
  );
}

// Added dark mode styles
function StatusBadge({ status }) {
  const colors = {
    "In Progress":
      "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200",
    Planning: "bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200",
    Completed:
      "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200",
    "On Hold": "bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200",
  };

  return (
    <span
      className={`px-2 py-1 inline-flex text-xs leading-5 font-semibold rounded-full ${
        colors[status] ||
        "bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200"
      }`}
    >
      {status}
    </span>
  );
}

// Added dark mode styles
function Th({ children }) {
  return (
    <th
      scope="col"
      className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider"
    >
      {children}
    </th>
  );
}

// Added dark mode styles
function Td({ children, className = "" }) {
  return (
    <td
      className={`px-6 py-4 whitespace-nowrap text-sm text-gray-700 dark:text-gray-300 ${className}`}
    >
      {children}
    </td>
  );
}
