import { useState } from 'react'
import './App.css'
import Nav from './components/Nav'
import About from './components/About'
import Projects from './components/Projects'

function App() {
  return (
    <>
      <Nav />
      <About />
      <Projects />
    </>
  )
}

export default App
