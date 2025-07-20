function Nav() {
    return (
        <nav className="navbar navbar-expand-lg navigation">
            <ul className="navbar-nav">
                <li className="nav-item">
                    <a className="nav-link" href="#">
                        Myself
                    </a>
                </li>
                <li className="nav-item">
                    <a className="nav-link" href="projects">
                        Projects
                    </a>
                </li>
                <li className="nav-item">
                    <a className="nav-link" href="#">
                        Talk to me
                    </a>
                </li>
            </ul>
        </nav>
    )
}

export default Nav;