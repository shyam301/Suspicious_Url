-- phpMyAdmin SQL Dump
-- version 4.0.4
-- http://www.phpmyadmin.net
--
-- Host: localhost
-- Generation Time: Dec 14, 2022 at 09:28 AM
-- Server version: 5.6.12-log
-- PHP Version: 5.4.12

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;

--
-- Database: `malicious`
--
CREATE DATABASE IF NOT EXISTS `malicious` DEFAULT CHARACTER SET latin1 COLLATE latin1_swedish_ci;
USE `malicious`;

-- --------------------------------------------------------

--
-- Table structure for table `regist`
--

CREATE TABLE IF NOT EXISTS `regist` (
  `uname` text NOT NULL,
  `pwd` text NOT NULL,
  `addr` text NOT NULL,
  `email` text NOT NULL,
  `mno` text NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `regist`
--

INSERT INTO `regist` (`uname`, `pwd`, `addr`, `email`, `mno`) VALUES
('anu', 'anu', 'anu cottage', 'anu@gmail.com', '9827343310'),
('kadhir', 'ka', 'kadhir cottage', 'ka@gmail.com', '8762534341');

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
