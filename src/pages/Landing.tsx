import React from 'react';
import Hero from '../components/landing/Hero';
import Features from '../components/landing/Features';
import Brokers from '../components/landing/Brokers';
import HowItWorks from '../components/landing/HowItWorks';
import Contact from '../components/landing/Contact';

const Landing: React.FC = () => {
  return (
    <div>
      <Hero />
      <Features />
      <Brokers />
      <HowItWorks />
      <Contact />
    </div>
  );
};

export default Landing;