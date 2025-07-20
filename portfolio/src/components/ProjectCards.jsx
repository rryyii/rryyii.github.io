function ProjectCards({ name, description, cover, tech }) {
    return (
        <div className="container">
            <div className="d-flex flex-column project-card">
                <img src={cover} alt="Cover image for a project"></img>
                <h1>{name}</h1>
                <h3 className="project-description">{description}</h3>
            </div>
        </div>
    )
}

export default ProjectCards;