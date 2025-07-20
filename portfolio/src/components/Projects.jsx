import ProjectCards from "./ProjectCards";

function Projects() {
    return (
        <div className="container" id="projects">
            <div className="d-flex gap-3">
                <ProjectCards name={"Ekada"} description={"Desktop application written in Java to track and display a users fitness and nutritional history. Uses Java Swing for its GUI for login and registering a user and displays the users current health statistics and exercise history. Visualizes exercise variance with a pie chart through the XChart library. Data storage and retrieval with an SQL database of the users information and exercise history."} cover={""} />
                <ProjectCards name={"Fitrack"} description={"Full stack web application using React and Node.js to display data from professional tier 1 League of Legends esports leagues. Express.js backend to handle GET requests to the Leaguepedia API."} cover={""} />
                <ProjectCards name={"ThoughtSwap"} description={"Web application using the Django framework that allows for discussion posts between facilitators and participants to communicate together. Utilizes web sockets through Django Channels to add responsiveness to a facilitators prompt."} cover={""} />
            </div>
        </div>
    )
}

export default Projects;